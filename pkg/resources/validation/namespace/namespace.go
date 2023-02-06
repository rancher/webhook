package namespace

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

const (
	manageNSVerb        = "manage-namespaces"
	projectNSAnnotation = "field.cattle.io/projectId"
)

var projectsGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "projects",
}

func NewValidator(sar authorizationv1.SubjectAccessReviewInterface) webhook.Handler {
	return &Validator{
		sar: sar,
	}
}

type Validator struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

// Admit ensures that the user has permission to change the namespace annotation for
// project membership, effectively moving a project from one namespace to another.
func (v *Validator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("Namespace Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	if request.Operation != admissionv1.Create && request.Operation != admissionv1.Update {
		// only handle create/update requests
		response.Allowed = true
		return nil
	}
	rawNs, err := request.DecodeObject()
	if err != nil {
		return fmt.Errorf("failed to decode namespace from request: %w", err)
	}
	ns, ok := rawNs.(*corev1.Namespace)
	if !ok {
		return fmt.Errorf("object on request was not a namesapce")
	}

	projectAnnoValue, ok := ns.Annotations[projectNSAnnotation]
	if !ok {
		// this namespace doesn't belong to a project, let standard RBAC handle it
		response.Allowed = true
		return nil
	}

	values := strings.Split(projectAnnoValue, ":")
	if len(values) < 2 {
		return fmt.Errorf("unable to retrieve project id from annotation, too few values")
	}
	projectName := values[1]
	// convert from one type of extras to another. Necessary since these two packages re-define extras
	extras := map[string]v1.ExtraValue{}
	for k, v := range request.UserInfo.Extra {
		extras[k] = v1.ExtraValue(v)
	}
	// check if the user has "manage-namespaces" on the project they are trying to target with this namespace
	sarResponse, err := v.sar.Create(request.Context, &v1.SubjectAccessReview{
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
		return fmt.Errorf("unable to create sar to check user permissions: %w", err)
	}

	if sarResponse.Status.Allowed {
		response.Allowed = true
		return nil
	}

	response.Allowed = false
	response.Result = &metav1.Status{
		Status:  "Failure",
		Message: sarResponse.Status.Reason,
		Reason:  metav1.StatusReasonUnauthorized,
		Code:    http.StatusForbidden,
	}
	return nil

}
