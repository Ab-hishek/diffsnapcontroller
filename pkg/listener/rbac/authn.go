package rbac

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

type AuthenticationMiddleware struct {
	kubeClient           kubernetes.Interface
	requestAuthenticator authenticator.Request
}

var (
	_ (authenticator.Request) = (*AuthenticationMiddleware)(nil)
)

// NewAuthenticationMiddleware creates an authenticator compatible with the kubelet's needs
func NewAuthenticationMiddleware(kubeClient kubernetes.Interface) (*AuthenticationMiddleware, error) {
	tokenClient := kubeClient.AuthenticationV1()
	if tokenClient == nil {
		return nil, errors.New("tokenAccessReview client not provided, cannot use webhook authentication")
	}

	authenticatorConfig := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:               false, // always require authentication
		CacheTTL:                2 * time.Minute,
		TokenAccessReviewClient: tokenClient,
		WebhookRetryBackoff:     options.DefaultAuthWebhookRetryBackoff(),
	}

	authenticator, _, err := authenticatorConfig.New()
	if err != nil {
		return nil, err
	}

	return &AuthenticationMiddleware{
		kubeClient:           kubeClient,
		requestAuthenticator: authenticator,
	}, nil
}

func (a *AuthenticationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authenticate
		user, ok, err := a.AuthenticateRequest(r)
		if err != nil {
			klog.Errorf("Unable to authenticate the request due to an error: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get authorization attributes
		allAttrs := GetRequestAttributes(user.User, r)
		if len(allAttrs) == 0 {
			msg := "Bad Request. The request or configuration is malformed."
			klog.V(2).Info(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		sarClient := a.kubeClient.AuthorizationV1()
		sarAuthorizer, err := NewSarAuthorizer(sarClient)
		if err != nil {
			klog.Fatalf("Failed to create sar authorizer: %v", err)
		}

		for _, attrs := range allAttrs {
			// Authorize request
			authorized, reason, err := sarAuthorizer.Authorize(context.TODO(), attrs)
			if err != nil {
				msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", user.User.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
				klog.Errorf("%s: %s", msg, err)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
			if authorized != authorizer.DecisionAllow {
				msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", user.User.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
				klog.V(2).Infof("%s. Reason: %q.", msg, reason)
				http.Error(w, msg, http.StatusForbidden)
				return
			}
		}

		// Pass down the request to the next middleware (or final handler)
		next.ServeHTTP(w, r)
	})
}

func (a *AuthenticationMiddleware) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	return a.requestAuthenticator.AuthenticateRequest(req)
}
