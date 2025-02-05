package namespace

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

const (
	fleetLocalNs        = "fleet-local"
	localNs             = "local"
	manageNSVerb        = "manage-namespaces"
	projectNSAnnotation = "field.cattle.io/projectId"
)

type projectNamespaceAdmitter struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

// Admit ensures that the:
//   - user has permission to change the namespace annotation for project membership, effectively moving a project from
//     one namespace to another.
//   - deletion of `local` and `fleet-local` namespace is not allowed
func (p *projectNamespaceAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("Namespace Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	response := &admissionv1.AdmissionResponse{}

	oldNs, newNs, err := objectsv1.NamespaceOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode namespace from request: %w", err)
	}

	if request.Operation == admissionv1.Delete {
		if oldNs.Name == localNs || oldNs.Name == fleetLocalNs {
			return admission.ResponseBadRequest(fmt.Sprintf("deletion of namespace %q is not allowed\n", request.Name)), nil
		}
	}
	projectAnnoValue, ok := newNs.Annotations[projectNSAnnotation]
	if !ok {
		// this namespace doesn't belong to a project, let standard RBAC handle it
		response.Allowed = true
		return response, nil
	}

	if request.Operation == admissionv1.Update {
		// only handle when project annotation is changing
		if oldAnnoValue, ok := oldNs.Annotations[projectNSAnnotation]; ok && oldAnnoValue == projectAnnoValue {
			response.Allowed = true
			return response, nil
		}
	}

	values := strings.Split(projectAnnoValue, ":")
	if len(values) < 2 {
		return nil, fmt.Errorf("unable to retrieve project id from annotation, too few values")
	}
	projectName := values[1]
	// convert from one type of extras to another. Necessary since these two packages re-define extras
	extras := map[string]v1.ExtraValue{}
	for k, v := range request.UserInfo.Extra {
		extras[k] = v1.ExtraValue(v)
	}
	// check if the user has "manage-namespaces" on the project they are trying to target with this namespace
	sarResponse, err := p.sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:     manageNSVerb,
				Group:    projectsGVR.Group,
				Version:  projectsGVR.Version,
				Resource: projectsGVR.Resource,
				Name:     projectName,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			UID:    request.UserInfo.UID,
			Extra:  extras,
		},
	}, metav1.CreateOptions{})

	if err != nil {
		return nil, err
	}

	if sarResponse.Status.Allowed {
		response.Allowed = true
		return response, nil
	}

	constructedReason := fmt.Sprintf("User %q does not have permission %q on project %q",
		request.UserInfo.Username, manageNSVerb, projectName)

	response.Allowed = false
	response.Result = &metav1.Status{
		Status:  "Failure",
		Message: constructedReason,
		Reason:  metav1.StatusReasonUnauthorized,
		Code:    http.StatusForbidden,
	}
	return response, nil
}
