package node

import (
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var nodeGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "nodes",
}

const localNs = "local"

type Validator struct {
	admitter admitter
}

type admitter struct{}

// Admit is the entrypoint for the validator. It lets a request through or prevent user from executing it.
func (a admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	oldNode, _, err := objectsv3.NodeOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new node from request: %w", err)
	}
	if request.Operation == admissionv1.Delete && oldNode.Namespace == localNs {
		// prevent deletion of nodes related to local cluster as it may result in its corruption
		return admission.ResponseBadRequest(fmt.Sprintf("cannot delete 'node.management.cattle.io' from namespace %q\n", localNs)), nil
	}

	return admission.ResponseAllowed(), nil
}

// NewValidator returns a new validator for management nodes
func NewValidator() *Validator {
	return &Validator{}
}

// GVR returns the GroupVersionResource for this CRD.
func (v Validator) GVR() schema.GroupVersionResource {
	return nodeGVR
}

// Operations returns list of operations handled by this validator.
func (v Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Delete, admissionregistrationv1.Create, admissionregistrationv1.Update}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())}
}

func (v Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}
