package authconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "authconfigs",
}

// Validator validates authconfigs.
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

type admitter struct {
}

// Admit handles the webhook admission requests.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("authconfigValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldAuthConfig, newAuthConfig, err := objectsv3.AuthConfigOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get AuthConfig from request: %w", err)
	}

	switch request.Operation {
	case admissionv1.Create:
		return a.admitCreate(request, newAuthConfig)
	case admissionv1.Update:
		return a.admitUpdate(request, oldAuthConfig, newAuthConfig)
	default:
		return admission.ResponseAllowed(), nil
	}
}

func (a *admitter) admitCreate(request *admission.Request, newAuthConfig *v3.AuthConfig) (*admissionv1.AdmissionResponse, error) {
	return a.admitCommonCreateUpdate(request, nil, newAuthConfig)
}

func (a *admitter) admitUpdate(request *admission.Request, oldAuthConfig, newAuthConfig *v3.AuthConfig) (*admissionv1.AdmissionResponse, error) {
	return a.admitCommonCreateUpdate(request, oldAuthConfig, newAuthConfig)
}

func (a *admitter) admitCommonCreateUpdate(request *admission.Request, _, newAuthConfig *v3.AuthConfig) (*admissionv1.AdmissionResponse, error) {
	var err error

	switch newAuthConfig.Type {
	case "openLdapConfig", "freeIpaConfig":
		err = validateLDAPConfig(request)
	case "activeDirectoryConfig":
		err = validateActiveDirectoryConfig(request)
	default:
	}

	if err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	return admission.ResponseAllowed(), nil
}

func validateLDAPConfig(request *admission.Request) error {
	var (
		err    error
		config v3.LdapConfig
	)

	if err = json.Unmarshal(request.Object.Raw, &config); err != nil {
		return fmt.Errorf("failed to get %T from request: %w", config, err)
	}

	if len(config.Servers) < 1 {
		err = errors.Join(err, field.Forbidden(field.NewPath("servers"), "at least one server is required"))
	}
	if config.TLS && config.Certificate == "" {
		err = errors.Join(err, field.Forbidden(field.NewPath("certificate"), "certificate is required"))
	}

	if config.UserSearchAttribute != "" {
		for _, attr := range strings.Split(config.UserSearchAttribute, "|") {
			if !IsValidAttr(attr) {
				err = errors.Join(err, field.Forbidden(field.NewPath("userSearchAttribute"), "invalid value"))
			}
		}
	}
	if config.UserLoginAttribute != "" && !IsValidAttr(config.UserLoginAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userLoginAttribute"), "invalid value"))
	}
	if config.UserObjectClass != "" && !IsValidAttr(config.UserObjectClass) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userObjectClass"), "invalid value"))
	}
	if config.UserNameAttribute != "" && !IsValidAttr(config.UserNameAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userNameAttribute"), "invalid value"))
	}
	if config.UserMemberAttribute != "" && !IsValidAttr(config.UserMemberAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userMemberAttribute"), "invalid value"))
	}
	if config.UserEnabledAttribute != "" && !IsValidAttr(config.UserEnabledAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userEnabledAttribute"), "invalid value"))
	}
	if config.GroupSearchAttribute != "" && !IsValidAttr(config.GroupSearchAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupSearchAttribute"), "invalid value"))
	}
	if config.GroupObjectClass != "" && !IsValidAttr(config.GroupObjectClass) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupObjectClass"), "invalid value"))
	}
	if config.GroupNameAttribute != "" && !IsValidAttr(config.GroupNameAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupNameAttribute"), "invalid value"))
	}
	if config.GroupDNAttribute != "" && !IsValidAttr(config.GroupDNAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupDNAttribute"), "invalid value"))
	}
	if config.GroupMemberUserAttribute != "" && !IsValidAttr(config.GroupMemberUserAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupMemberUserAttribute"), "invalid value"))
	}
	if config.GroupMemberMappingAttribute != "" && !IsValidAttr(config.GroupMemberMappingAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupMemberMappingAttribute"), "invalid value"))
	}

	if config.UserLoginFilter != "" {
		if _, fieldErr := ldapv3.CompileFilter(config.UserLoginFilter); fieldErr != nil {
			err = errors.Join(err, field.Forbidden(field.NewPath("userLoginFilter"), fmt.Sprintf("%s", fieldErr)))
		}
	}
	if config.UserSearchFilter != "" {
		if _, fieldErr := ldapv3.CompileFilter(config.UserSearchFilter); fieldErr != nil {
			err = errors.Join(err, field.Forbidden(field.NewPath("userSearchFilter"), fmt.Sprintf("%s", fieldErr)))
		}
	}
	if config.GroupSearchFilter != "" {
		if _, fieldErr := ldapv3.CompileFilter(config.GroupSearchFilter); fieldErr != nil {
			err = errors.Join(err, field.Forbidden(field.NewPath("groupSearchFilter"), fmt.Sprintf("%s", fieldErr)))
		}
	}

	return err
}

func validateActiveDirectoryConfig(request *admission.Request) error {
	var (
		err    error
		config v3.ActiveDirectoryConfig
	)

	if err = json.Unmarshal(request.Object.Raw, &config); err != nil {
		return fmt.Errorf("failed to get %T from request: %w", config, err)
	}

	if len(config.Servers) < 1 {
		err = errors.Join(err, field.Forbidden(field.NewPath("servers"), "at least one server is required"))
	}
	if config.TLS && config.Certificate == "" {
		err = errors.Join(err, field.Forbidden(field.NewPath("certificate"), "certificate is required"))
	}

	if config.UserSearchAttribute != "" {
		for _, attr := range strings.Split(config.UserSearchAttribute, "|") {
			if !IsValidAttr(attr) {
				err = errors.Join(err, field.Forbidden(field.NewPath("userSearchAttribute"), "invalid value "+attr))
			}
		}
	}
	if config.UserLoginAttribute != "" && !IsValidAttr(config.UserLoginAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userLoginAttribute"), "invalid value"))
	}
	if config.UserObjectClass != "" && !IsValidAttr(config.UserObjectClass) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userObjectClass"), "invalid value"))
	}
	if config.UserNameAttribute != "" && !IsValidAttr(config.UserNameAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userNameAttribute"), "invalid value"))
	}
	if config.UserEnabledAttribute != "" && !IsValidAttr(config.UserEnabledAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userEnabledAttribute"), "invalid value"))
	}
	if config.GroupSearchAttribute != "" && !IsValidAttr(config.GroupSearchAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupSearchAttribute"), "invalid value"))
	}
	if config.GroupObjectClass != "" && !IsValidAttr(config.GroupObjectClass) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupObjectClass"), "invalid value"))
	}
	if config.GroupNameAttribute != "" && !IsValidAttr(config.GroupNameAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupNameAttribute"), "invalid value"))
	}
	if config.GroupDNAttribute != "" && !IsValidAttr(config.GroupDNAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupDNAttribute"), "invalid value"))
	}
	if config.GroupMemberUserAttribute != "" && !IsValidAttr(config.GroupMemberUserAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupMemberUserAttribute"), "invalid value"))
	}
	if config.GroupMemberMappingAttribute != "" && !IsValidAttr(config.GroupMemberMappingAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupMemberMappingAttribute"), "invalid value"))
	}

	if config.UserLoginFilter != "" {
		if _, fieldErr := ldapv3.CompileFilter(config.UserLoginFilter); fieldErr != nil {
			err = errors.Join(err, field.Forbidden(field.NewPath("userLoginFilter"), fmt.Sprintf("%s", fieldErr)))
		}
	}
	if config.UserSearchFilter != "" {
		if _, fieldErr := ldapv3.CompileFilter(config.UserSearchFilter); fieldErr != nil {
			err = errors.Join(err, field.Forbidden(field.NewPath("userSearchFilter"), fmt.Sprintf("%s", fieldErr)))
		}
	}
	if config.GroupSearchFilter != "" {
		if _, fieldErr := ldapv3.CompileFilter(config.GroupSearchFilter); fieldErr != nil {
			err = errors.Join(err, field.Forbidden(field.NewPath("groupSearchFilter"), fmt.Sprintf("%s", fieldErr)))
		}
	}

	return err
}

// According to RFC4512, attribute names (descriptors) should adhere to the following syntax
// descr = keystring
// keystring = leadkeychar *keychar
// leadkeychar = ALPHA
// keychar = ALPHA / DIGIT / HYPHEN
// See https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
var validAttr = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\-]*$`)

// IsValidAttr returns true is the given attribute name conforms with the syntax defined in RFC4512.
func IsValidAttr(attr string) bool {
	return validAttr.MatchString(attr)
}
