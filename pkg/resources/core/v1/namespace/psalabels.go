package namespace

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

const (
	updatePSAVerb = "updatepsa"
	projectId     = "field.cattle.io/projectId"
)

type psaLabelAdmitter struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

// Admit ensures that users have sufficient permissions to add/remove PSAs to a namespace.
func (p *psaLabelAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {

	if request.Operation == admissionv1.Delete {
		return admission.ResponseAllowed(), nil
	}

	listTrace := trace.New("Namespace Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	response := &admissionv1.AdmissionResponse{}

	var ns, oldns *corev1.Namespace
	var err error
	// Is the request attempting to modify the special PSA labels (enforce, warn, audit)?
	// If it isn't, we're done.
	// If it is, we then need to check to see if they should be allowed.
	switch request.Operation {
	case admissionv1.Create:
		ns, err = objectsv1.NamespaceFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to decode namespace from request: %w", err)
		}
		if !common.IsCreatingPSAConfig(ns.Labels) {
			response.Allowed = true
			return response, nil
		}
	case admissionv1.Update:
		oldns, ns, err = objectsv1.NamespaceOldAndNewFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to decode namespace from request: %w", err)
		}
		if !common.IsUpdatingPSAConfig(oldns.Labels, ns.Labels) {
			response.Allowed = true
			return response, nil
		}
	}

	extras := map[string]v1.ExtraValue{}
	for k, v := range request.UserInfo.Extra {
		extras[k] = v1.ExtraValue(v)
	}

	var projectNamespace, projectName string
	// here we are filling the variables above with the projectId,
	// so that if we are not able to get them,
	// the SAR request will be done in any case.
	if ns.Annotations[projectId] != "" {
		projectInfo := strings.Split(ns.Annotations[projectId], ":")
		if len(projectInfo) == 2 {
			projectNamespace = projectInfo[0]
			projectName = projectInfo[1]
		}
	}

	fmt.Println("SAR:")
	fmt.Println("verb:", updatePSAVerb)
	fmt.Println("group:", projectsGVR.Group)
	fmt.Println("version:", projectsGVR.Version)
	fmt.Println("resource:", projectsGVR.Resource)
	fmt.Println("user:", request.UserInfo.Username)
	fmt.Println("groups:", request.UserInfo.Groups)
	fmt.Println("uid:", request.UserInfo.UID)
	fmt.Println("extra:", request.UserInfo.Extra)
	fmt.Println("ns:", projectNamespace)
	fmt.Println("name:", projectName)
	fmt.Println("===========>")
	sarReq := &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:      updatePSAVerb,
				Group:     projectsGVR.Group,
				Version:   projectsGVR.Version,
				Resource:  projectsGVR.Resource,
				Namespace: projectNamespace,
				Name:      projectName,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			UID:    request.UserInfo.UID,
			Extra:  extras,
		},
	}

	resp, err := p.sar.Create(request.Context, sarReq, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("SAR request creation failed: %w", err)
	}
	fmt.Println("allowed:", resp.Status.Allowed)
	fmt.Println("denied:", resp.Status.Denied)
	fmt.Println("err:", resp.Status.EvaluationError)
	fmt.Println("reason:", resp.Status.Reason)

	if resp.Status.Allowed {
		response.Allowed = true
		fmt.Println("allowed")
	} else {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: resp.Status.Reason,
			Reason:  metav1.StatusReasonUnauthorized,
			Code:    http.StatusForbidden,
		}
		fmt.Println("denied")
	}
	fmt.Println()
	return response, nil
}
