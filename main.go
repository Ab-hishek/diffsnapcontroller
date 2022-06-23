/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"time"

	snapshotclientset "github.com/kubernetes-csi/external-snapshotter/client/v4/clientset/versioned"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	// Uncomment the following line to load the gcp plugin (only required to authenticate against GKE clusters).
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/phuongatemc/diffsnapcontroller/pkg/controller"
	clientset "github.com/phuongatemc/diffsnapcontroller/pkg/generated/clientset/versioned"
	informers "github.com/phuongatemc/diffsnapcontroller/pkg/generated/informers/externalversions"
	"github.com/phuongatemc/diffsnapcontroller/pkg/listener"
	"github.com/phuongatemc/diffsnapcontroller/pkg/server"
	"github.com/phuongatemc/diffsnapcontroller/pkg/signals"
)

var (
	masterURL  string
	kubeconfig string
	csiAddress string
)

const (
	CONTROLLER_NAMESPACE = "testns"
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// set up signals so we handle the first shutdown signal gracefully
	stopCh := signals.SetupSignalHandler()

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		klog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.Fatalf("Error building kubernetes clientset: %s", err.Error())
	}

	diffsnapClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		klog.Fatalf("Error building diffsnap clientset: %s", err.Error())
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(kubeClient, time.Second*30)
	diffsnapInformerFactory := informers.NewSharedInformerFactory(diffsnapClient, time.Second*30)

	klog.Infof("csi address: %v", csiAddress)
	snapshotClientSet, err := snapshotclientset.NewForConfig(cfg)
	if err != nil {
		klog.Fatalf("unable to get Snapshot ClientSet %v", err.Error())
	}
	controller := controller.NewController(kubeClient, diffsnapClient, snapshotClientSet,
		diffsnapInformerFactory.Differentialsnapshot().V1alpha1().VolumeSnapshotDeltas())

	// create a new listener service
	listener, err := listener.NewListener(csiAddress)
	if err != nil {
		klog.Fatalf("Error creating a listener service: %s", err.Error())
	}

	// start the listener service in a separate thread
	go listener.StartListener()

	// notice that there is no need to run Start methods in a separate goroutine. (i.e. go kubeInformerFactory.Start(stopCh)
	// Start method is non-blocking and runs all registered informers in a dedicated goroutine.
	kubeInformerFactory.Start(stopCh)
	diffsnapInformerFactory.Start(stopCh)

	// Start listner
	l := &server.Listner{KubeClient: kubeClient}
	go l.Run(ctx)

	if err = controller.Run(2, stopCh); err != nil {
		klog.Fatalf("Error running controller: %s", err.Error())
	}
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&csiAddress, "csi-address", "/run/csi/socket", "Address of the CSI driver socket.")

}
