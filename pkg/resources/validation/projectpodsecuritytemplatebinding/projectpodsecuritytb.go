// Package projectpodsecuritytemplatebinding is used for validating
// projectpodsecuritytemplatebinding admission requests.
package projectpodsecuritytemplatebinding

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"

	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"

	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

// NewValidator returns a new validator used for validation of PPSTB.
func NewValidator(sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{
		sar: sar,
	}
}

// Validator validates the PPSTB admission request
type Validator struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

// Admit is the entrypoint for the validator.
// Admit will return an error if it unable to process the request.
func (c *Validator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("projectPodSecurityTBValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	// We need to check permission on the target project rather than the cluster level
	// so we fetch the psptpb and get the TargetProjectName to use that in our SAR
	psptpb, err := objectsv3.PodSecurityPolicyTemplateProjectBindingFromRequest(request)
	if err != nil {
		response.Result.Code = http.StatusBadRequest
		return fmt.Errorf("failed to decode PSPTPB from request: %w", err)
	}
	parts := strings.Split(psptpb.TargetProjectName, ":")
	if len(parts) != 2 {
		response.Result.Code = http.StatusBadRequest
		return fmt.Errorf("invalid project ID given in request: %s", psptpb.TargetProjectName)
	}
	targetProject := parts[1]

	var sarVerb string
	if request.Operation == admissionv1.Update {
		sarVerb = "update"
	} else if request.Operation == admissionv1.Create {
		sarVerb = "create"
	}
	resp, err := c.sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Name:      psptpb.Name,
				Verb:      sarVerb,
				Version:   "v3",
				Resource:  "podsecuritypolicytemplateprojectbindings",
				Group:     "management.cattle.io",
				Namespace: targetProject,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if resp.Status.Allowed {
		response.Allowed = true
	} else {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: resp.Status.Reason,
			Reason:  metav1.StatusReasonUnauthorized,
			Code:    http.StatusForbidden,
		}
	}
	return nil
}
