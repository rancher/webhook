// Package capautils provides shared constants and helpers for the
// infrastructure.cluster.x-k8s.io/v1beta2 webhook validators.
package capautils

import (
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

const (
	// AnnotationSourceID is the annotation key placed on CAPA objects by Rancher
	// Turtles to mark them as Rancher-managed. Credential access checks are only
	// enforced when this annotation is present on the AWSClusterStaticIdentity.
	AnnotationSourceID = "cluster-api.cattle.io/source-id"

	// RancherCredentialsNamespace is the namespace where Rancher Cloud Credential
	// secrets are stored and where SubjectAccessReview checks are performed.
	RancherCredentialsNamespace = "cattle-global-data"
)

// SecretGVR is the GroupVersionResource for core/v1 Secrets.
var SecretGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "secrets",
}

// HasSourceIDAnnotation reports whether obj carries the Rancher Turtles
// source annotation, indicating it is a Rancher-managed CAPA resource.
func HasSourceIDAnnotation(obj metav1.Object) bool {
	return obj.GetAnnotations()[AnnotationSourceID] != ""
}

// CheckSecretAccess performs a SubjectAccessReview to verify that the user in
// request has GET permission on the Secret named secretName in
// RancherCredentialsNamespace. It returns:
//   - (ResponseAllowed, nil)   when access is granted
//   - (403 response, nil)      when access is denied
//   - (nil, error)             when the SAR call itself fails
func CheckSecretAccess(request *admission.Request, secretName string, sar authorizationv1.SubjectAccessReviewInterface) (*admissionv1.AdmissionResponse, error) {
	allowed, err := auth.RequestUserHasVerb(request, SecretGVR, sar, "get", secretName, RancherCredentialsNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to perform access review for secret %s/%s: %w",
			RancherCredentialsNamespace, secretName, err)
	}
	if !allowed {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status: "Failure",
				Message: fmt.Sprintf("user %q does not have permission to get secret %s/%s",
					request.UserInfo.Username, RancherCredentialsNamespace, secretName),
				Reason: metav1.StatusReasonForbidden,
				Code:   http.StatusForbidden,
			},
		}, nil
	}
	return admission.ResponseAllowed(), nil
}
