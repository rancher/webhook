// Package capautils provides shared constants and helpers for the
// infrastructure.cluster.x-k8s.io/v1beta2 webhook validators.
package capautils

import (
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	corev1controller "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

const (
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

// IsMirroredCloudCredential reports whether a Secret named secretName exists
// in RancherCredentialsNamespace (cattle-global-data), indicating it is a
// Rancher Cloud Credential that Turtles has mirrored into the CAPA provider
// namespace.
//
// Returns (true, nil) when the secret is found — SAR should be enforced.
// Returns (false, nil) when the secret is not found — user-managed, allow.
// Returns (false, err) on any other cache error — callers should fail closed.
func IsMirroredCloudCredential(secretName string, secretCache corev1controller.SecretCache) (bool, error) {
	_, err := secretCache.Get(RancherCredentialsNamespace, secretName)
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("failed to check secret %s/%s: %w", RancherCredentialsNamespace, secretName, err)
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
				Status:  "Failure",
				Message: "requesting user does not have access to the referenced secret",
				Reason:  metav1.StatusReasonForbidden,
				Code:    http.StatusForbidden,
			},
		}, nil
	}
	return admission.ResponseAllowed(), nil
}
