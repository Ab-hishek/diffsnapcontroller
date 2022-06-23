package listener

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/kubernetes-csi/csi-lib-utils/connection"
	"github.com/kubernetes-csi/csi-lib-utils/metrics"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	changeblockservice "github.com/phuongatemc/diffsnapcontroller/pkg/changedblockservice/changed_block_service"
	"github.com/phuongatemc/diffsnapcontroller/pkg/controller"
	"github.com/phuongatemc/diffsnapcontroller/pkg/listener/rbac"
	"github.com/phuongatemc/diffsnapcontroller/pkg/listener/schema"
)

var (
	listenerPort string = ":8000"
)

type Listener struct {
	httpServer                     *mux.Router
	differentialSnapshotGrpcClient changeblockservice.DifferentialSnapshotClient
	kubeClient                     kubernetes.Interface
}

func NewListener(kubeClient kubernetes.Interface, csiAddress string) (*Listener, error) {
	metricsManager := metrics.NewCSIMetricsManagerForSidecar("cbt-service")
	//create client
	csiConn, err := connection.Connect(
		csiAddress,
		metricsManager,
		connection.OnConnectionLoss(connection.ExitOnConnectionLoss()))
	if err != nil {
		return nil, err
	}

	cbtGrpcClient := changeblockservice.NewDifferentialSnapshotClient(csiConn)

	listener := &Listener{
		httpServer:                     mux.NewRouter(),
		differentialSnapshotGrpcClient: cbtGrpcClient,
		kubeClient:                     kubeClient,
	}
	return listener, nil
}

func (l Listener) StartListener() {
	l.httpServer.HandleFunc(fmt.Sprintf("/{%s}/{%s}/changedblocks", schema.CRNamespaceParam, schema.CRNameParam), l.ServeHttpRequestHandler).Methods("GET")

	// Add rbac middleware
	am, err := rbac.NewAuthenticationMiddleware(l.kubeClient)
	if err != nil {
		klog.Fatalf("Failed to instantiate delegating authenticator: %v", err)
	}
	l.httpServer.Use(am.Middleware)

	// start listening
	klog.Fatalf("%v", http.ListenAndServe(listenerPort, l.httpServer))
}

func (l Listener) ServeHttpRequestHandler(resp http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	snapshotDeltaCrName := vars[schema.CRNameParam]

	// get the start-offset embedded as a query parameter in the request URL
	startOffset := req.URL.Query().Get("startoffset")

	if _, ok := controller.DSMap[snapshotDeltaCrName]; !ok {
		klog.Errorf("Missing VolumeSnapshotDelta CR details")
		http.Error(resp, "Unable to get VolumeSnapshotDelta details", http.StatusInternalServerError)
		return
	}

	cbs, err := l.differentialSnapshotGrpcClient.GetChangedBlocks(context.TODO(), &changeblockservice.GetChangedBlocksRequest{
		SnapshotBase:   controller.DSMap[snapshotDeltaCrName].BaseVS.Name,
		SnapshotTarget: controller.DSMap[snapshotDeltaCrName].TargetVS.Name,
		StartOfOffset:  startOffset,
		MaxEntries:     controller.DSMap[snapshotDeltaCrName].MaxEntries,
	})
	if err != nil {
		klog.Errorf("Unable to get changed blocks from listener service: %v", err)
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}
	klog.Infof("Processed GetChangedBlocks %#v", cbs)

	var changedBlocks []schema.ChangedBlock

	for _, cb := range cbs.ChangedBlocks {
		changedBlocks = append(changedBlocks, schema.ChangedBlock{
			Offset:  cb.Offset,
			Size:    cb.Size,
			Context: cb.Context,
			ZeroOut: cb.ZeroOut,
		})
	}

	// Send a success response along with the payload
	respondWithJSON(resp, http.StatusOK, schema.ChangeBlocksResponse{
		ChangeBlockList: changedBlocks,
		NextOffset:      cbs.NextOffSet,
		VolumeSize:      cbs.VolumeSize,
		Timeout:         cbs.Timeout,
	})
}

func respondWithJSON(resp http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(code)
	resp.Write(response)
}
