package setting

import (
	"errors"
	"fmt"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/robfig/cron"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/trace"

	"github.com/rancher/webhook/pkg/admission"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
)

// MinDeleteInactiveUserAfter is the minimum duration for delete-inactive-user-after setting.
// This is introduced to minimize the risk of deleting users accidentally by setting a relatively low value.
// The admin can still set a lower value if needed by bypassing the webhook.
const MinDeleteInactiveUserAfter = 24 * 14 * time.Hour // 14 days.

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "settings",
}

// Validator validates settings.
type Validator struct {
	admitter admitter
}

// NewValidator returns a new Validator instance.
func NewValidator(clusterCache controllerv3.ClusterCache) *Validator {
	return &Validator{
		admitter: admitter{
			clusterCache: clusterCache,
		},
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
	valWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())
	valWebhook.FailurePolicy = admission.Ptr(admissionregistrationv1.Ignore)
	return []admissionregistrationv1.ValidatingWebhook{*valWebhook}
}

// Admitters returns the admitter objects.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	clusterCache controllerv3.ClusterCache
}

// Admit handles the webhook admission requests.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("userAttributeValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldSetting, newSetting, err := objectsv3.SettingOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get Setting from request: %w", err)
	}
	switch request.Operation {
	case admissionv1.Create:
		if err := a.validateUserRetentionSettings(newSetting); err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
	case admissionv1.Update:
		if err := a.validateUserRetentionSettings(newSetting); err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		if err := a.validateAgentTLSMode(*oldSetting, *newSetting); err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
	}
	return admission.ResponseAllowed(), nil
}

func (a *admitter) validateUserRetentionSettings(s *v3.Setting) error {
	var err error

	switch s.Name {
	case "disable-inactive-user-after":
		if s.Value != "" {
			_, err = validateDuration(s.Value)
		}
	case "delete-inactive-user-after":
		if s.Value != "" {
			var dur time.Duration
			dur, err = validateDuration(s.Value)
			if err == nil && dur < MinDeleteInactiveUserAfter {
				err = fmt.Errorf("must be at least %s", MinDeleteInactiveUserAfter)
			}
		}
	case "user-last-login-default":
		if s.Value != "" {
			_, err = time.Parse(time.RFC3339, s.Value)
		}
	case "user-retention-cron":
		if s.Value != "" {
			_, err = cron.ParseStandard(s.Value)
		}
	default:
	}

	if err != nil {
		return field.TypeInvalid(field.NewPath("value"), s.Value, err.Error())
	}

	return nil
}

func (a *admitter) validateAgentTLSMode(oldSetting, newSetting v3.Setting) error {
	if oldSetting.Name != "agent-tls-mode" || newSetting.Name != "agent-tls-mode" {
		return nil
	}
	if effectiveValue(oldSetting) == "system-store" && effectiveValue(newSetting) == "strict" {
		if force := newSetting.Annotations["cattle.io/force"]; force == "true" {
			return nil
		}
		clusters, err := a.clusterCache.List(labels.NewSelector())
		if err != nil {
			return fmt.Errorf("failed to list clusters: %w", err)
		}
		for _, cluster := range clusters {
			if cluster.Name == "local" {
				continue
			}
			if !clusterConditionMatches(cluster, "AgentTlsStrictCheck", "True") {
				return field.Forbidden(field.NewPath("value", "default"),
					fmt.Sprintf("AgentTlsStrictCheck condition of cluster %s isn't 'True'", cluster.Name))
			}
		}
	}
	return nil
}

func validateDuration(value string) (time.Duration, error) {
	dur, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}

	if dur < 0 {
		return 0, errors.New("negative duration")
	}

	return dur, err
}

func clusterConditionMatches(cluster *v3.Cluster, t v3.ClusterConditionType, status v1.ConditionStatus) bool {
	for _, cond := range cluster.Status.Conditions {
		if cond.Type == t && cond.Status == status {
			return true
		}
	}
	return false
}

func effectiveValue(s v3.Setting) string {
	if s.Value != "" {
		return s.Value
	} else if s.Default != "" {
		return s.Default
	}
	return ""
}
