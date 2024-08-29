package setting

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/trace"
)

const (
	DeleteInactiveUserAfter   = "delete-inactive-user-after"
	DisableInactiveUserAfter  = "disable-inactive-user-after"
	AuthUserSessionTTLMinutes = "auth-user-session-ttl-minutes"
	UserLastLoginDefault      = "user-last-login-default"
	UserRetentionCron         = "user-retention-cron"
	AgentTLSMode              = "agent-tls-mode"
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

var valuePath = field.NewPath("value")

// Validator validates settings.
type Validator struct {
	admitter admitter
}

// NewValidator returns a new Validator instance.
func NewValidator(clusterCache controllerv3.ClusterCache, settingCache controllerv3.SettingCache) *Validator {
	return &Validator{
		admitter: admitter{
			clusterCache: clusterCache,
			settingCache: settingCache,
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
	settingCache controllerv3.SettingCache
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
		return a.admitCommonCreateUpdate(oldSetting, newSetting)
	case admissionv1.Update:
		if err := a.validateAgentTLSMode(oldSetting, newSetting); err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		return a.admitCommonCreateUpdate(oldSetting, newSetting)
	}
	return admission.ResponseAllowed(), nil
}

func (a *admitter) admitCommonCreateUpdate(_, newSetting *v3.Setting) (*admissionv1.AdmissionResponse, error) {
	if err := a.validateUserRetentionSettings(newSetting); err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	if err := a.validateAuthUserSessionTTLMinutes(newSetting); err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	return admission.ResponseAllowed(), nil
}

func (a *admitter) validateAuthUserSessionTTLMinutes(s *v3.Setting) error {
	if s.Name != AuthUserSessionTTLMinutes {
		return nil
	}

	if s.Value == "" {
		return nil
	}

	userSessionDuration, err := parseMinutes(s.Value)
	if err != nil {
		return field.TypeInvalid(valuePath, s.Value, err.Error())
	}
	if userSessionDuration < 0 {
		return field.TypeInvalid(valuePath, s.Value, "negative value")
	}

	isGreaterThanSetting := func(name string) bool {
		setting, err := a.settingCache.Get(name)
		if err != nil {
			logrus.Warnf("failed to get %s: %s", name, err)
			return false // Deliberately allow to proceed.
		}

		settingDur, err := time.ParseDuration(effectiveValue(setting))
		if err != nil {
			logrus.Warnf("failed to parse %s: %s", name, err)
			return false // Deliberately allow to proceed.
		}

		return settingDur > 0 && userSessionDuration > settingDur
	}

	checkAgainst := []string{DisableInactiveUserAfter, DeleteInactiveUserAfter}

	for _, name := range checkAgainst {
		if isGreaterThanSetting(name) {
			return field.TypeInvalid(valuePath, s.Value, "can't be greater than "+name)
		}
	}

	return nil
}

func (a *admitter) validateUserRetentionSettings(s *v3.Setting) error {
	var (
		err error
		dur time.Duration
	)

	isLessThanUserSessionTTL := func(dur time.Duration) bool {
		setting, err := a.settingCache.Get(AuthUserSessionTTLMinutes)
		if err != nil {
			logrus.Warnf("failed to get %s: %v", AuthUserSessionTTLMinutes, err)
			return false // Deliberately allow to proceed.
		}

		authUserSessionTTLDuration, err := parseMinutes(effectiveValue(setting))
		if err != nil {
			logrus.Warnf("failed to parse %s: %s", AuthUserSessionTTLMinutes, err)
			return false // Deliberately allow to proceed.
		}

		return dur < authUserSessionTTLDuration
	}

	lessThanAuthUserSessionTTLErr := fmt.Errorf("can't be less than %s", AuthUserSessionTTLMinutes)
	switch s.Name {
	case DisableInactiveUserAfter:
		if s.Value != "" {
			dur, err = validateDuration(s.Value)
			if err == nil && dur > 0 && isLessThanUserSessionTTL(dur) { // Note: zero duration is allowed and is equivalent to "".
				err = lessThanAuthUserSessionTTLErr
			}
		}
	case DeleteInactiveUserAfter:
		minDeleteInactiveUserAfterErr := fmt.Errorf("must be at least %s", MinDeleteInactiveUserAfter)
		if s.Value != "" {
			dur, err = validateDuration(s.Value)
			if err == nil && dur > 0 { // Note: zero duration is allowed and is equivalent to "".
				if dur < MinDeleteInactiveUserAfter {
					err = minDeleteInactiveUserAfterErr
				} else if isLessThanUserSessionTTL(dur) {
					err = lessThanAuthUserSessionTTLErr
				}
			}
		}
	case UserLastLoginDefault:
		if s.Value != "" {
			_, err = time.Parse(time.RFC3339, s.Value)
		}
	case UserRetentionCron:
		if s.Value != "" {
			_, err = cron.ParseStandard(s.Value)
		}
	default:
	}

	if err != nil {
		return field.TypeInvalid(valuePath, s.Value, err.Error())
	}

	return nil
}

// validateDuration parses the value as durations and makes sure it's not negative.
func validateDuration(value string) (time.Duration, error) {
	dur, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}

	if dur < 0 {
		return 0, errors.New("negative value")
	}

	return dur, err
}

// parseMinutes parses the value as minutes as returns the duration.
func parseMinutes(value string) (time.Duration, error) {
	minutes, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}

	return time.Duration(minutes) * time.Minute, nil
}

func (a *admitter) validateAgentTLSMode(oldSetting, newSetting *v3.Setting) error {
	if oldSetting.Name != AgentTLSMode || newSetting.Name != AgentTLSMode {
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

func clusterConditionMatches(cluster *v3.Cluster, t v3.ClusterConditionType, status v1.ConditionStatus) bool {
	for _, cond := range cluster.Status.Conditions {
		if cond.Type == t && cond.Status == status {
			return true
		}
	}

	return false
}

// effectiveValue returns the effective value of the setting.
func effectiveValue(s *v3.Setting) string {
	if s.Value != "" {
		return s.Value
	} else if s.Default != "" {
		return s.Default
	}

	return ""
}
