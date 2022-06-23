/*
Copyright 2017 The Kubernetes Authors.

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

package controller

import (
	"context"
	"fmt"
	"time"

	snapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v4/apis/volumesnapshot/v1"
	snapshotclientset "github.com/kubernetes-csi/external-snapshotter/client/v4/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	differentialsnapshotv1alpha1 "github.com/phuongatemc/diffsnapcontroller/pkg/apis/differentialsnapshot/v1alpha1"
	clientset "github.com/phuongatemc/diffsnapcontroller/pkg/generated/clientset/versioned"
	informers "github.com/phuongatemc/diffsnapcontroller/pkg/generated/informers/externalversions/differentialsnapshot/v1alpha1"
	listers "github.com/phuongatemc/diffsnapcontroller/pkg/generated/listers/differentialsnapshot/v1alpha1"
)

const (
	controllerAgentName = "differentialsnapshot"
	// SuccessSynced is used as part of the Event 'reason' when a VolumeSnapshotDelta is synced
	SuccessSynced = "Synced"
	// MessageResourceSynced is the message used for an Event fired when a VolumeSnapshotDelta
	// is synced successfully
	MessageResourceSynced = "VolumeSnapshotDelta synced successfully"
	BaseURL               = "testURL" // "podDNSName:portNumber"
)

// Controller is the controller implementation for VolumeSnapshotDelta resources
type Controller struct {
	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface
	// sampleclientset is a clientset for our own API group
	diffSnapClient            clientset.Interface
	snapshotClientSet         snapshotclientset.Interface
	volumeSnapshotDeltaLister listers.VolumeSnapshotDeltaLister
	volumeSnapshotDeltaSynced cache.InformerSynced

	// workqueue is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens. This
	// means we can ensure we only process a fixed amount of resources at a
	// time, and makes it easy to ensure we are never processing the same item
	// simultaneously in two different workers.
	workqueue workqueue.RateLimitingInterface
	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder
}

// NewController returns a new diffsnap controller
func NewController(
	kubeclientset kubernetes.Interface,
	diffSnapClient clientset.Interface,
	snapshotClientSet snapshotclientset.Interface,
	volumeSnapshotDeltaInformer informers.VolumeSnapshotDeltaInformer) *Controller {

	// Create event broadcaster
	// Add differentialsnapshot types to the default Kubernetes Scheme so Events can be
	// logged for differentialsnapshot types.
	utilruntime.Must(differentialsnapshotv1alpha1.AddToScheme(scheme.Scheme))
	klog.V(4).Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartStructuredLogging(0)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := &Controller{
		kubeclientset:             kubeclientset,
		diffSnapClient:            diffSnapClient,
		snapshotClientSet:         snapshotClientSet,
		volumeSnapshotDeltaLister: volumeSnapshotDeltaInformer.Lister(),
		volumeSnapshotDeltaSynced: volumeSnapshotDeltaInformer.Informer().HasSynced,
		workqueue:                 workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "VolumeSnapshotDelta"),
		recorder:                  recorder,
	}

	klog.Info("Setting up event handlers")
	// Set up an event handler for when VolumeSnapshotDelta resources change
	volumeSnapshotDeltaInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueVolumeSnapshotDelta,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueVolumeSnapshotDelta(new)
		},
	})

	return controller
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	klog.Info("Starting VolumeSnapshotDelta controller")

	// Wait for the caches to be synced before starting workers
	klog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.volumeSnapshotDeltaSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	klog.Info("Starting workers")
	// Launch two workers to process VolumeSnapshotDelta resources
	for i := 0; i < workers; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	klog.Info("Started workers")
	<-stopCh
	klog.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.workqueue.Done(obj)
		var key string
		var ok bool
		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the syncHandler, passing it the namespace/name string of the
		// VolumeSnapshotDelta resource to be synced.
		if err := c.syncHandler(key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.workqueue.Forget(obj)
		klog.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the VolumeSnapshotDelta resource
// with the current status of the resource.
func (c *Controller) syncHandler(key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the VolumeSnapshotDelta resource with this namespace/name
	volumeSnapshotDelta, err := c.volumeSnapshotDeltaLister.VolumeSnapshotDeltas(namespace).Get(name)
	if err != nil {
		// The VolumeSnapshotDelta resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("volumeSnapshotDelta '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}
	klog.Infof("Processing VolumeSnapshotDelta %s", volumeSnapshotDelta.Name)
	targetVS, targetVSC, baseVS, baseVSC, driverName, err := validateVolumeSnapshotDelta(
		context.TODO(), c.snapshotClientSet, volumeSnapshotDelta)
	if err != nil {
		klog.Errorf("Unable to get changed blocks from service: %v", err)
		volumeSnapshotDelta.Status.State = "Failed"
		volumeSnapshotDelta.Status.Error = err.Error()
		volumeSnapshotDelta, err = c.updateVolumeSnapshotDeltaStatus(volumeSnapshotDelta)
		if err != nil {
			klog.Errorf("unable to update the VolumeSnapshotDelta status: %v", err)
			return err
		}
		return err
	}
	resource := &VolumeSnapshotDeltaResource{
		TargetVS:   targetVS,
		TargetVSC:  targetVSC,
		BaseVS:     baseVS,
		BaseVSC:    baseVSC,
		Driver:     driverName,
		MaxEntries: volumeSnapshotDelta.Spec.MaxEntries,
	}
	DSMap[volumeSnapshotDelta.Name] = resource

	klog.Infof("Processed VolumeSnapshotDelta %s", volumeSnapshotDelta.Name)
	volumeSnapshotDelta.Status.State = "Success"
	volumeSnapshotDelta.Status.StreamURL = fmt.Sprintf("%s/%s/%s", BaseURL,
		volumeSnapshotDelta.Namespace, volumeSnapshotDelta.Name)
	klog.Infof("Processed VolumeSnapshotDelta name: %v, output: %v", volumeSnapshotDelta.Name, volumeSnapshotDelta)

	volumeSnapshotDelta.Status.State = "Success"
	klog.Infof("Processed VolumeSnapshotDelta name: %v, output: %v", volumeSnapshotDelta.Name, volumeSnapshotDelta)
	volumeSnapshotDelta, err = c.updateVolumeSnapshotDeltaStatus(volumeSnapshotDelta)
	if err != nil {
		klog.Errorf("unable to update the CBT status: %v", err)
		return err
	}

	c.recorder.Event(volumeSnapshotDelta, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)

	return err
}

type VolumeSnapshotDeltaResource struct {
	Driver     string
	TargetVS   *snapshotv1.VolumeSnapshot
	TargetVSC  *snapshotv1.VolumeSnapshotContent
	BaseVS     *snapshotv1.VolumeSnapshot
	BaseVSC    *snapshotv1.VolumeSnapshotContent
	MaxEntries uint64
}

// Shared resource map between DiffSnap Controller and DiffSnap Service/Listener.
var DSMap map[string]*VolumeSnapshotDeltaResource

func init() {
	DSMap = make(map[string]*VolumeSnapshotDeltaResource)
}

func validateVolumeSnapshotDelta(
	ctx context.Context,
	snapshotClientSet snapshotclientset.Interface,
	volumeSnapshotDelta *differentialsnapshotv1alpha1.VolumeSnapshotDelta) (
	targetVS *snapshotv1.VolumeSnapshot, targetVSC *snapshotv1.VolumeSnapshotContent,
	baseVS *snapshotv1.VolumeSnapshot, baseVSC *snapshotv1.VolumeSnapshotContent, driver string, err error) {
	if volumeSnapshotDelta.Spec.TargetVolumeSnapshotName == "" {
		err = fmt.Errorf("Missing TargetVolumeSnapshotName.")
		return
	}
	namespace := volumeSnapshotDelta.Namespace
	// fetch VolumeSnapshot, VolumeSnapshotContent and validate them
	targetVS, targetVSC, err = validateVolumeSnapshot(ctx, snapshotClientSet, namespace, volumeSnapshotDelta.Spec.TargetVolumeSnapshotName)
	if err != nil {
		return
	}
	driver = targetVSC.Spec.Driver
	if driver == "" {
		err = fmt.Errorf("VolumeSnapshotContent '%s' missing Driver.", targetVSC.Name)
	}
	if volumeSnapshotDelta.Spec.BaseVolumeSnapshotName != "" {
		baseVS, baseVSC, err = validateVolumeSnapshot(ctx, snapshotClientSet, namespace, volumeSnapshotDelta.Spec.BaseVolumeSnapshotName)
	}

	err = validateCSIDriver(driver)

	return
}

func validateCSIDriver(driveName string) (err error) {
	// TODO: validate CSI Driver to make sure it supports DIFFERENTIAL_SNAPSHOT
	return
}

func validateVolumeSnapshot(
	ctx context.Context,
	snapshotClientSet snapshotclientset.Interface,
	namespace string,
	volumeSnapshotName string) (vs *snapshotv1.VolumeSnapshot, vsc *snapshotv1.VolumeSnapshotContent, err error) {

	klog.Infof("Validating VolumeSnapshot '%s'...", volumeSnapshotName)
	vs, err = snapshotClientSet.SnapshotV1().VolumeSnapshots(namespace).Get(ctx, volumeSnapshotName, metav1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("Unable to retrieve VolumeSnapshot '%s': %s.", volumeSnapshotName, err)
		return
	}
	klog.Infof("VolumeSnapshot '%s' is valid.", volumeSnapshotName)
	snapshotContentName := vs.Status.BoundVolumeSnapshotContentName
	if snapshotContentName == nil {
		err = fmt.Errorf("VolumeSnapshot '%s' missing BoundVolumeSnapshotContentName.", vs.Name)
		return
	}
	klog.Infof("Validating VolumeSnapshotContent '%s'...", *snapshotContentName)
	vsc, err = snapshotClientSet.SnapshotV1().VolumeSnapshotContents().Get(ctx, *snapshotContentName, metav1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("Unable to get volumesnapshotcontent '%s': %s", *snapshotContentName, err)
		return
	}
	klog.Infof("VolumeSnapshotContent '%s' is valid.", *snapshotContentName)
	return
}

func (c *Controller) updateVolumeSnapshotDeltaStatus(
	volumeSnapshotDelta *differentialsnapshotv1alpha1.VolumeSnapshotDelta) (
	updatedVolumeSnapshotDelta *differentialsnapshotv1alpha1.VolumeSnapshotDelta, err error) {
	volumeSnapshotDeltaCopy := volumeSnapshotDelta.DeepCopy()

	updatedVolumeSnapshotDelta, err = c.diffSnapClient.DifferentialsnapshotV1alpha1().VolumeSnapshotDeltas(
		volumeSnapshotDelta.Namespace).UpdateStatus(context.TODO(), volumeSnapshotDeltaCopy, metav1.UpdateOptions{})
	return
}

// enqueueVolumeSnapshotDelta takes a VolumeSnapshotDelta resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than VolumeSnapshotDelta.
func (c *Controller) enqueueVolumeSnapshotDelta(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueue.Add(key)
}
