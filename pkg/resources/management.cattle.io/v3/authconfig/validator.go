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

	if !newAuthConfig.Enabled {
		// Validate the config only if the auth provider is enabled.
		return admission.ResponseAllowed(), nil
	}

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

	if config.UserSearchAttribute != "" {
		for _, attr := range strings.Split(config.UserSearchAttribute, "|") {
			if !IsValidLdapAttr(attr) {
				err = errors.Join(err, field.Forbidden(field.NewPath("userSearchAttribute"), "invalid value"))
			}
		}
	}
	if config.UserLoginAttribute != "" && !IsValidLdapAttr(config.UserLoginAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userLoginAttribute"), "invalid value"))
	}
	if config.UserObjectClass != "" && !IsValidLdapAttr(config.UserObjectClass) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userObjectClass"), "invalid value"))
	}
	if config.UserNameAttribute != "" && !IsValidLdapAttr(config.UserNameAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userNameAttribute"), "invalid value"))
	}
	if config.UserMemberAttribute != "" && !IsValidLdapAttr(config.UserMemberAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userMemberAttribute"), "invalid value"))
	}
	if config.UserEnabledAttribute != "" && !IsValidLdapAttr(config.UserEnabledAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userEnabledAttribute"), "invalid value"))
	}
	if config.GroupSearchAttribute != "" && !IsValidLdapAttr(config.GroupSearchAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupSearchAttribute"), "invalid value"))
	}
	if config.GroupObjectClass != "" && !IsValidLdapAttr(config.GroupObjectClass) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupObjectClass"), "invalid value"))
	}
	if config.GroupNameAttribute != "" && !IsValidLdapAttr(config.GroupNameAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupNameAttribute"), "invalid value"))
	}
	if config.GroupDNAttribute != "" && !IsValidLdapAttr(config.GroupDNAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupDNAttribute"), "invalid value"))
	}
	if config.GroupMemberUserAttribute != "" && !IsValidLdapAttr(config.GroupMemberUserAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupMemberUserAttribute"), "invalid value"))
	}
	if config.GroupMemberMappingAttribute != "" && !IsValidLdapAttr(config.GroupMemberMappingAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupMemberMappingAttribute"), "invalid value"))
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

	if config.UserSearchAttribute != "" {
		for _, attr := range strings.Split(config.UserSearchAttribute, "|") {
			if !IsValidLdapAttr(attr) {
				err = errors.Join(err, field.Forbidden(field.NewPath("userSearchAttribute"), "invalid value "+attr))
			}
		}
	}
	if config.UserLoginAttribute != "" && !IsValidLdapAttr(config.UserLoginAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userLoginAttribute"), "invalid value"))
	}
	if config.UserObjectClass != "" && !IsValidLdapAttr(config.UserObjectClass) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userObjectClass"), "invalid value"))
	}
	if config.UserNameAttribute != "" && !IsValidLdapAttr(config.UserNameAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userNameAttribute"), "invalid value"))
	}
	if config.UserEnabledAttribute != "" && !IsValidLdapAttr(config.UserEnabledAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("userEnabledAttribute"), "invalid value"))
	}
	if config.GroupSearchAttribute != "" && !IsValidLdapAttr(config.GroupSearchAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupSearchAttribute"), "invalid value"))
	}
	if config.GroupObjectClass != "" && !IsValidLdapAttr(config.GroupObjectClass) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupObjectClass"), "invalid value"))
	}
	if config.GroupNameAttribute != "" && !IsValidLdapAttr(config.GroupNameAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupNameAttribute"), "invalid value"))
	}
	if config.GroupDNAttribute != "" && !IsValidLdapAttr(config.GroupDNAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupDNAttribute"), "invalid value"))
	}
	if config.GroupMemberUserAttribute != "" && !IsValidLdapAttr(config.GroupMemberUserAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupMemberUserAttribute"), "invalid value"))
	}
	if config.GroupMemberMappingAttribute != "" && !IsValidLdapAttr(config.GroupMemberMappingAttribute) {
		err = errors.Join(err, field.Forbidden(field.NewPath("groupMemberMappingAttribute"), "invalid value"))
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

// According to RFC4512 https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
// Object identifiers (OIDs) [X.680] are represented in LDAP using a
// dot-decimal format conforming to the ABNF:
//
//	numericoid = number 1*( DOT number )
//
// Short names, also known as descriptors, are used as more readable
// aliases for object identifiers.  Short names are case insensitive and
// conform to the ABNF:
//
//	descr = keystring
//
// Where either an object identifier or a short name may be specified,
// the following production is used:
//
//	oid = descr / numericoid
//
// Where
//
//	descr = keystring
//	keystring = leadkeychar *keychar
//	leadkeychar = ALPHA
//	keychar = ALPHA / DIGIT / HYPHEN
//	number  = DIGIT / ( LDIGIT 1*DIGIT )
//
//	ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
//	DIGIT   = %x30 / LDIGIT       ; "0"-"9"
//	LDIGIT  = %x31-39             ; "1"-"9"
//	HYPHEN  = %x2D ; hyphen ("-")
//	DOT     = %x2E ; period (".")
var (
	shortNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\-]*$`)
	oidRegex       = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*$`)
)

// IsValidLdapAttr returns true is the given attribute name conforms with
// either numeric OID or short name format.
// Note: this must match the corresponding validation logic in rancher/rancher.
func IsValidLdapAttr(attr string) bool {
	if shortNameRegex.MatchString(attr) {
		return true
	}
	if oidRegex.MatchString(attr) {
		return true
	}
	return false
}
