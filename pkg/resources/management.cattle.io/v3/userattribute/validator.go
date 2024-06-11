package userattribute

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "userattributes",
}

// Validator validates userattributes.
type Validator struct {
	admitter admitter
}

// NewValidator returns a new Validator instance.
func NewValidator() *Validator {
	return &Validator{
		admitter: admitter{},
	}
}

// GVR returns the GroupVersionResource.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by the validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create}
}

// ValidatingWebhook returns the ValidatingWebhook.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{
		*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations()),
	}
}

// Admitters returns the admitter objects.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct{}

// Admit handles the webhook admission requests.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("userAttributeValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	if request.Operation == admissionv1.Create || request.Operation == admissionv1.Update {
		err := a.validateRetentionFields(request)
		if err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
	}

	return admission.ResponseAllowed(), nil
}

// PartialUserAttribute represents raw values of UserAttribute retention fields.
type PartialUserAttribute struct {
	LastLogin    *string `json:"lastLogin"`
	DisableAfter *string `json:"disableAfter"`
	DeleteAfter  *string `json:"deleteAfter"`
}

func (a *admitter) validateRetentionFields(request *admission.Request) error {
	var (
		attr PartialUserAttribute
		dur  time.Duration
	)

	err := json.Unmarshal(request.Object.Raw, &attr)
	if err != nil {
		return fmt.Errorf("failed to get PartialUserAttribute from request: %w", err)
	}

	if attr.LastLogin != nil {
		if _, err = time.Parse(time.RFC3339, *attr.LastLogin); err != nil {
			return field.TypeInvalid(field.NewPath("lastLogin"), attr.LastLogin, err.Error())
		}
	}

	if attr.DisableAfter != nil {
		if dur, err = time.ParseDuration(*attr.DisableAfter); err != nil {
			return field.TypeInvalid(field.NewPath("disableAfter"), *attr.DisableAfter, err.Error())
		}
		if dur < 0 {
			return field.Invalid(field.NewPath("disableAfter"), *attr.DisableAfter, "negative duration")
		}
	}

	if attr.DeleteAfter != nil {
		if dur, err = time.ParseDuration(*attr.DeleteAfter); err != nil {
			return field.TypeInvalid(field.NewPath("deleteAfter"), *attr.DeleteAfter, err.Error())
		}
		if dur < 0 {
			return field.Invalid(field.NewPath("deleteAfter"), *attr.DeleteAfter, "negative duration")
		}
	}

	return nil
}
