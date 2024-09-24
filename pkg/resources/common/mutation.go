package common

import (
	"github.com/rancher/webhook/pkg/admission"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetCreatorIDAnnotation sets the creatorID Annotation on the newObj based  on the user specified in the request.
// If the noCreatorRBAC annotation is set, don't set the creator
func SetCreatorIDAnnotation(request *admission.Request, newObj metav1.Object) {
	annotations := newObj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	// NoCreatorRBACAnn indicates we want to opt out of the CreatorIDAnn
	if _, ok := annotations[NoCreatorRBACAnn]; ok {
		return
	}

	annotations[CreatorIDAnn] = request.UserInfo.Username
	newObj.SetAnnotations(annotations)
}
