// Package nodedriver handles validation and creation for rke1 and rke2 nodedrivers.
package nodedriver

import (
	"fmt"

	"github.com/rancher/lasso/pkg/dynamic"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	controllersv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	gvr = schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "nodedrivers",
	}

	driverInUse = &admissionv1.AdmissionResponse{
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: "This driver is in use by existing nodes and cannot be disabled",
		},
		Allowed: false,
	}
)

// Validator ValidatingWebhook for NodeDrivers
type Validator struct {
	admitter admitter
}

type admitter struct {
	nodeCache controllersv3.NodeCache
	crdCache  generic.NonNamespacedCacheInterface[*v1.CustomResourceDefinition]
	dynamic   dynamicLister
}

// dynamicLister is an interface to abstract away how we list dynamic objects from k8s
type dynamicLister interface {
	List(gvk schema.GroupVersionKind, namespace string, selector labels.Selector) ([]runtime.Object, error)
}

// NewValidator returns a new Validator for NodeDriver resources
func NewValidator(nodeCache controllersv3.NodeCache, dynamic *dynamic.Controller, crdCache generic.NonNamespacedCacheInterface[*v1.CustomResourceDefinition]) admission.ValidatingAdmissionHandler {
	return &Validator{admitter: admitter{
		nodeCache: nodeCache,
		crdCache:  crdCache,
		dynamic:   dynamic,
	}}
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Delete}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())}
}

// Admitters returns the admitter objects used to validate machineconfigs.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

// Admit is the entrypoint for the validator. Admit will return an error if it unable to process the request.
// If this function is called without NewValidator(..) calls will panic.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	oldObject, newObject, err := objectsv3.NodeDriverOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode object from request: %w", err)
	}

	// the check to see if the driver is being disabled is either when we're
	// running a delete operation OR an update operation where the active flag
	// toggles from true -> false
	if !(request.Operation == admissionv1.Delete && oldObject.Spec.Active) &&
		!(request.Operation == admissionv1.Update && !newObject.Spec.Active && oldObject.Spec.Active) {
		return admission.ResponseAllowed(), nil
	}

	// check if all node resources have been deleted for both cluster types
	rke1Deleted, err := a.rke1ResourcesDeleted(oldObject)
	if err != nil {
		return nil, err
	}
	rke2Deleted, err := a.rke2ResourcesDeleted(oldObject)
	if err != nil {
		return nil, err
	}

	if !(rke1Deleted && rke2Deleted) {
		return driverInUse, nil
	}

	return admission.ResponseAllowed(), nil
}

// // RKE1
// this one is a bit more clean since we're just looking at nodes with
// the <displayname> provider
func (a *admitter) rke1ResourcesDeleted(driver *v3.NodeDriver) (bool, error) {
	nodes, err := a.nodeCache.List("", labels.Everything())
	if err != nil {
		return false, fmt.Errorf("error listing nodes from cache: %w", err)
	}

	for _, node := range nodes {
		if node.Status.NodeTemplateSpec == nil {
			continue
		}

		if node.Status.NodeTemplateSpec.Driver == driver.Name {
			return false, nil
		}
	}

	return true, nil
}

// // RKE2
// this one is pretty weird since we have to get the name of the CR we're
// looking from the Name of the driver.
func (a *admitter) rke2ResourcesDeleted(driver *v3.NodeDriver) (bool, error) {
	gvk := schema.GroupVersionKind{
		Group:   "rke-machine.cattle.io",
		Version: "v1",
		Kind:    driver.Name + "machine",
	}

	_, err := a.crdCache.Get(fmt.Sprintf("%ss.%s", gvk.Kind, gvk.Group))
	if err != nil {
		if apierrors.IsNotFound(err) {
			// in this case the CRD just isn't present for the NodeDriver itself or
			// hasn't been created yet. If there isn't a CRD -> there can't be any
			// machines so we authorize the request
			logrus.Debugf("CRD Not found for %s when disabling NodeDriver, admitting request", gvk)
			return true, nil
		}

		return false, fmt.Errorf("error fetching CRD from cache: %w", err)
	}

	machines, err := a.dynamic.List(gvk, "", labels.Everything())
	if err != nil {
		return false, fmt.Errorf("error listing %smachines: %w", driver.Name, err)
	}

	if len(machines) != 0 {
		return false, nil
	}

	return true, nil
}
