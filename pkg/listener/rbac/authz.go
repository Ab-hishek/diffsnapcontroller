package rbac

import (
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/options"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/klog/v2"

	differentialsnapshotv1alpha1 "github.com/phuongatemc/diffsnapcontroller/pkg/apis/differentialsnapshot/v1alpha1"
	"github.com/phuongatemc/diffsnapcontroller/pkg/listener/schema"
)

const volumeSnapshotDeltaResource = "volumesnapshotdeltas"

// NewSarAuthorizer creates an authorizer compatible with the kubelet's needs
func NewSarAuthorizer(client authorizationclient.AuthorizationV1Interface) (authorizer.Authorizer, error) {
	if client == nil {
		return nil, errors.New("no client provided, cannot use webhook authorization")
	}
	authorizerConfig := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: client,
		AllowCacheTTL:             5 * time.Minute,
		DenyCacheTTL:              30 * time.Second,
		WebhookRetryBackoff:       options.DefaultAuthWebhookRetryBackoff(),
	}
	return authorizerConfig.New()
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func GetRequestAttributes(u user.Info, r *http.Request) []authorizer.Attributes {
	apiVerb := ""
	switch r.Method {
	case "POST":
		apiVerb = "create"
	case "GET":
		apiVerb = "get"
	case "PUT":
		apiVerb = "update"
	case "PATCH":
		apiVerb = "patch"
	case "DELETE":
		apiVerb = "delete"
	}

	var allAttrs []authorizer.Attributes

	defer func() {
		for _, attrs := range allAttrs {
			klog.V(5).Infof("kube-rbac-proxy request attributes: attrs=%#+v", attrs)
		}
	}()

	// Protect endpoint
	// Default attributes mirror the API attributes that would allow this access to kube-rbac-proxy
	allAttrs = append(allAttrs, authorizer.AttributesRecord{
		User:            u,
		Verb:            apiVerb,
		Namespace:       "",
		APIGroup:        "",
		APIVersion:      "",
		Resource:        "",
		Subresource:     "",
		Name:            "",
		ResourceRequest: false,
		Path:            "/",
	})

	params := mux.Vars(r)
	crName := params[schema.CRNameParam]
	crNamespace := params[schema.CRNamespaceParam]

	// Protect CR
	allAttrs = append(allAttrs, authorizer.AttributesRecord{
		User:            u,
		Verb:            apiVerb,
		Namespace:       crNamespace,
		APIGroup:        differentialsnapshotv1alpha1.SchemeGroupVersion.Group,
		APIVersion:      differentialsnapshotv1alpha1.SchemeGroupVersion.Version,
		Resource:        volumeSnapshotDeltaResource,
		Name:            crName,
		ResourceRequest: true,
	})
	return allAttrs
}
