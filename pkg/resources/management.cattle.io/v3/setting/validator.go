package setting

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/trace"
)

const (
	DeleteInactiveUserAfter               = "delete-inactive-user-after"
	DisableInactiveUserAfter              = "disable-inactive-user-after"
	AuthUserSessionTTLMinutes             = "auth-user-session-ttl-minutes"
	AuthUserSessionIdleTTLMinutes         = "auth-user-session-idle-ttl-minutes"
	UserLastLoginDefault                  = "user-last-login-default"
	UserRetentionCron                     = "user-retention-cron"
	AgentTLSMode                          = "agent-tls-mode"
	CattleClusterAgentPriorityClass       = "cluster-agent-default-priority-class"
	CattleClusterAgentPodDisruptionBudget = "cluster-agent-default-pod-disruption-budget"
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
	listTrace := trace.New("settingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldSetting, newSetting, err := objectsv3.SettingOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get Setting from request: %w", err)
	}

	switch request.Operation {
	case admissionv1.Create:
		return a.admitCreate(newSetting)
	case admissionv1.Update:
		return a.admitUpdate(oldSetting, newSetting)
	default:
		return admission.ResponseAllowed(), nil
	}
}

func (a *admitter) admitCreate(newSetting *v3.Setting) (*admissionv1.AdmissionResponse, error) {
	return a.admitCommonCreateUpdate(nil, newSetting)
}

func (a *admitter) admitUpdate(oldSetting, newSetting *v3.Setting) (*admissionv1.AdmissionResponse, error) {
	var err error

	switch newSetting.Name {
	case AgentTLSMode:
		err = a.validateAgentTLSMode(oldSetting, newSetting)
	case CattleClusterAgentPriorityClass:
		err = a.validateClusterAgentPriorityClass(newSetting)
	case CattleClusterAgentPodDisruptionBudget:
		err = a.validateClusterAgentPodDisruptionBudget(newSetting)
	default:
	}

	if err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	return a.admitCommonCreateUpdate(oldSetting, newSetting)
}

func (a *admitter) admitCommonCreateUpdate(_, newSetting *v3.Setting) (*admissionv1.AdmissionResponse, error) {
	var err error

	switch newSetting.Name {
	case DeleteInactiveUserAfter:
		err = a.validateDeleteInactiveUserAfter(newSetting)
	case DisableInactiveUserAfter:
		err = a.validateDisableInactiveUserAfter(newSetting)
	case UserLastLoginDefault:
		err = a.validateUserLastLoginDefault(newSetting)
	case UserRetentionCron:
		err = a.validateUserRetentionCron(newSetting)
	case AuthUserSessionTTLMinutes:
		err = a.validateAuthUserSessionTTLMinutes(newSetting)
	case AuthUserSessionIdleTTLMinutes:
		err = a.validateAuthUserSessionIdleTTLMinutes(newSetting)
	default:
	}

	if err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	return admission.ResponseAllowed(), nil
}

// validateAuthUserSessionTTLMinutes validates the auth-user-session-ttl-minutes setting
// to make sure it's a positive integer and that duration is not greater than
// {disable|delete}-inactive-user-after settings if they are set.
// If it encounters an error fetching or parsing {disable|delete}-inactive-user-after settings
// it logs but doesn't return the error to avoid rejecting the request.
func (a *admitter) validateAuthUserSessionTTLMinutes(s *v3.Setting) error {
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
			logrus.Warnf("[settingValidator] Failed to get %s: %s", name, err)
			return false // Deliberately allow to proceed.
		}

		settingDur, err := time.ParseDuration(effectiveValue(setting))
		if err != nil {
			logrus.Warnf("[settingValidator] Failed to parse %s: %s", name, err)
			return false // Deliberately allow to proceed.
		}

		return settingDur > 0 && userSessionDuration > settingDur
	}

	checkAgainst := []string{DisableInactiveUserAfter, DeleteInactiveUserAfter}

	for _, name := range checkAgainst {
		if isGreaterThanSetting(name) {
			return field.Forbidden(valuePath, "can't be greater than "+name)
		}
	}

	return nil
}

// validateAuthUserSessionIdleTTLMinutes validates the auth-user-session-idle-ttl-minutes setting
// to make sure it's a positive integer and that duration is not greater than
// auth-user-session-ttl-minutes settings if they are set.
// If it encounters an error fetching or parsing auth-user-session-ttl-minutes settings
// it logs but doesn't return the error to avoid rejecting the request.
func (a *admitter) validateAuthUserSessionIdleTTLMinutes(s *v3.Setting) error {
	if s.Value == "" {
		return nil
	}

	userSessionIdleDuration, err := parseMinutes(s.Value)
	if err != nil {
		return field.TypeInvalid(valuePath, s.Value, err.Error())
	}
	if userSessionIdleDuration < 1 {
		return field.TypeInvalid(valuePath, s.Value, "negative value or less than 1 minute")
	}

	isGreaterThanSetting := func(name string) bool {
		setting, err := a.settingCache.Get(name)
		if err != nil {
			logrus.Warnf("[settingValidator] Failed to get %s: %s", name, err)
			return false // Deliberately allow to proceed.
		}

		// auth-user-session-ttl-minutes is expressed as minutes,
		// so we use parseMinutes to compare it with the new
		// auth-user-session-idle-ttl-minutes setting.
		settingDur, err := parseMinutes(effectiveValue(setting))
		if err != nil {
			logrus.Warnf("[settingValidator] Failed to parse %s: %s", name, err)
			return false // Deliberately allow to proceed.
		}

		// since auth-user-session-ttl-minutes = 0 is an available value,
		// we check it as: settingDur >= 0.
		return settingDur >= 0 && userSessionIdleDuration > settingDur
	}

	// if auth-user-session-idle-ttl-minutes > auth-user-usesison-ttl-minutes
	if isGreaterThanSetting(AuthUserSessionTTLMinutes) {
		return field.Forbidden(valuePath, "can't be greater than "+AuthUserSessionTTLMinutes)
	}

	return nil
}

var errLessThanAuthUserSessionTTL = fmt.Errorf("can't be less than %s", AuthUserSessionTTLMinutes)

// isLessThanUserSessionTTL checks if the given duration is less than the value of
// auth-user-session-ttl-minutes setting.
// If it encounters an error fetching or parsing auth-user-session-ttl-minutes setting
// it logs the error and returns false to avoid rejecting the request.
func (a *admitter) isLessThanUserSessionTTL(dur time.Duration) bool {
	setting, err := a.settingCache.Get(AuthUserSessionTTLMinutes)
	if err != nil {
		logrus.Warnf("[settingValidator] Failed to get %s: %v", AuthUserSessionTTLMinutes, err)
		return false // Deliberately allow to proceed.
	}

	authUserSessionTTLDuration, err := parseMinutes(effectiveValue(setting))
	if err != nil {
		logrus.Warnf("[settingValidator] Failed to parse %s: %s", AuthUserSessionTTLMinutes, err)
		return false // Deliberately allow to proceed.
	}

	return dur < authUserSessionTTLDuration
}

// validateDisableInactiveUserAfter validates the disable-inactive-user-after setting
// to make sure it's a positive duration and that it's not less than the value of
// auth-user-session-ttl-minutes setting.
func (a *admitter) validateDisableInactiveUserAfter(s *v3.Setting) error {
	if s.Value == "" {
		return nil
	}

	dur, err := validateDuration(s.Value)
	if err != nil {
		return field.TypeInvalid(valuePath, s.Value, err.Error())
	}

	// Note: zero duration is allowed and is equivalent to "".
	if dur > 0 && a.isLessThanUserSessionTTL(dur) {
		return field.Forbidden(valuePath, errLessThanAuthUserSessionTTL.Error())
	}

	return nil
}

// validateDeleteInactiveUserAfter validates the delete-inactive-user-after setting
// to make sure it's a positive duration and that it's not less than the value of
// auth-user-session-ttl-minutes setting and MinDeleteInactiveUserAfter.
func (a *admitter) validateDeleteInactiveUserAfter(s *v3.Setting) error {
	if s.Value == "" {
		return nil
	}

	dur, err := validateDuration(s.Value)
	if err != nil {
		return field.TypeInvalid(valuePath, s.Value, err.Error())
	}

	// Note: zero duration is allowed and is equivalent to "".
	if dur > 0 {
		if dur < MinDeleteInactiveUserAfter {
			err = fmt.Errorf("must be at least %s", MinDeleteInactiveUserAfter)
		} else if a.isLessThanUserSessionTTL(dur) {
			err = errLessThanAuthUserSessionTTL
		}
	}

	if err != nil {
		return field.Forbidden(valuePath, err.Error())
	}

	return nil
}

// validateUserRetentionCron validates the user-retention-cron setting
// to make sure it's a valid standard cron expression.
func (a *admitter) validateUserRetentionCron(s *v3.Setting) error {
	if s.Value == "" {
		return nil
	}

	if _, err := cron.ParseStandard(s.Value); err != nil {
		return field.TypeInvalid(valuePath, s.Value, err.Error())
	}

	return nil
}

// validateUserLastLoginDefault validates the user-last-login-default setting
// to make sure it's a valid RFC3339 formatted date time.
func (a *admitter) validateUserLastLoginDefault(s *v3.Setting) error {
	if s.Value == "" {
		return nil
	}

	if _, err := time.Parse(time.RFC3339, s.Value); err != nil {
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

func (a *admitter) validateClusterAgentPriorityClass(newSetting *v3.Setting) error {
	if newSetting.Value == "" {
		return nil
	}

	pc := provv1.PriorityClassSpec{}

	err := json.Unmarshal([]byte(newSetting.Value), &pc)
	if err != nil {
		return err
	}

	if pc.Value > 1000000000 {
		return fmt.Errorf("value must be less than 1 billion and greater than negative 1 billion")
	}

	if pc.Value < -1000000000 {
		return fmt.Errorf("value must be less than 1 billion and greater than negative 1 billion")
	}

	if pc.Preemption != nil && *pc.Preemption != corev1.PreemptNever && *pc.Preemption != corev1.PreemptLowerPriority && *pc.Preemption != "" {
		return fmt.Errorf("preemption policy must be set to either 'Never' or 'PreemptLowerPriority'")
	}

	return nil
}

func (a *admitter) validateClusterAgentPodDisruptionBudget(newSetting *v3.Setting) error {
	if newSetting.Value == "" {
		return nil
	}

	pdb := provv1.PodDisruptionBudgetSpec{}

	err := json.Unmarshal([]byte(newSetting.Value), &pdb)
	if err != nil {
		return err
	}

	minAvailIsString := false
	maxUnavailIsString := false
	minAvailStr := pdb.MinAvailable
	maxUnavailStr := pdb.MaxUnavailable

	minAvailInt, err := strconv.Atoi(pdb.MinAvailable)
	if err != nil {
		minAvailIsString = true
	}

	maxUnavailInt, err := strconv.Atoi(pdb.MaxUnavailable)
	if err != nil {
		maxUnavailIsString = true
	}

	// can't set a non-zero value on both fields at the same time
	if (minAvailStr == "" && maxUnavailStr == "") ||
		(minAvailStr != "" && minAvailStr != "0") && (maxUnavailStr != "" && maxUnavailStr != "0") {
		return fmt.Errorf("both minAvailable and maxUnavailable cannot be set to a non zero value, at least one must be set to zero")
	}

	if minAvailInt < 0 {
		return fmt.Errorf("minAvailable cannot be set to a negative integer")
	}

	if maxUnavailInt < 0 {
		return fmt.Errorf("maxUnavailable cannot be set to a negative integer")
	}

	if minAvailIsString && !common.PdbPercentageRegex.Match([]byte(minAvailStr)) {
		return fmt.Errorf("minAvailable must be a non-negative whole integer or a percentage value between 0 and 100, regex used is '%s'", common.PdbPercentageRegex.String())
	}

	if maxUnavailIsString && !common.PdbPercentageRegex.Match([]byte(maxUnavailStr)) {
		return fmt.Errorf("minAvailable must be a non-negative whole integer or a percentage value between 0 and 100, regex used is '%s'", common.PdbPercentageRegex.String())
	}

	return nil
}

func clusterConditionMatches(cluster *v3.Cluster, t v3.ClusterConditionType, status corev1.ConditionStatus) bool {
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
	}

	if s.Default != "" {
		return s.Default
	}

	return ""
}
