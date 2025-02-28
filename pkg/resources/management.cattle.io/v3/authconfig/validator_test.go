package authconfig_test

import (
	"context"
	"encoding/json"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/authconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	gvk = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "AuthConfig"}
	gvr = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "authconfigs"}
)

func TestValidateLdapConfig(t *testing.T) {
	t.Parallel()

	fields := v3.LdapFields{
		Servers:                     []string{"ldap.example.com"},
		TLS:                         true,
		Certificate:                 "CERTIFICATE",
		UserSearchAttribute:         "uid|sn|givenName",
		UserLoginAttribute:          "uid",
		UserObjectClass:             "inetOrgPerson",
		UserNameAttribute:           "cn",
		UserMemberAttribute:         "memberOf",
		UserEnabledAttribute:        "userAccountControl",
		GroupSearchAttribute:        "cn",
		GroupObjectClass:            "groupOfNames",
		GroupNameAttribute:          "cn",
		GroupDNAttribute:            "entryDN",
		GroupMemberUserAttribute:    "entryDN",
		GroupMemberMappingAttribute: "member",
		UserLoginFilter:             "(&(status=active)(canLogin=true))",
		UserSearchFilter:            "(status=active)",
		GroupSearchFilter:           "(depNo=123)",
	}
	invalidAttr := "1foo"     // Leading digit.
	invalidFilter := "cn=foo" // No parentheses.

	tests := []struct {
		desc     string
		fields   func() v3.LdapFields
		disabled bool // Whether the auth provider is disabled.
		allowed  bool
	}{
		{
			desc:    "valid config",
			allowed: true,
		},
		{
			desc: "servers not specified",
			fields: func() v3.LdapFields {
				fields := fields
				fields.Servers = nil
				return fields
			},
		},
		{
			desc: "servers not specified for the disabled provider",
			fields: func() v3.LdapFields {
				fields := fields
				fields.Servers = nil
				return fields
			},
			disabled: true,
			allowed:  true,
		},
		{
			desc: "tls is on without certificate",
			fields: func() v3.LdapFields {
				fields := fields
				fields.Certificate = ""
				return fields
			},
		},
		{
			desc: "invalid UserSearchAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.UserSearchAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid UserLoginAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.UserLoginAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid UserObjectClass",
			fields: func() v3.LdapFields {
				fields := fields
				fields.UserObjectClass = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid UserNameAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.UserNameAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid UserMemberAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.UserMemberAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid UserEnabledAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.UserEnabledAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid GroupSearchAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.GroupSearchAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid GroupObjectClass",
			fields: func() v3.LdapFields {
				fields := fields
				fields.GroupObjectClass = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid GroupNameAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.GroupNameAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid GroupDNAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.GroupDNAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid GroupMemberUserAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.GroupMemberUserAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid GroupMemberMappingAttribute",
			fields: func() v3.LdapFields {
				fields := fields
				fields.GroupMemberMappingAttribute = invalidAttr
				return fields
			},
		},
		{
			desc: "invalid UserLoginFilter",
			fields: func() v3.LdapFields {
				fields := fields
				fields.UserLoginFilter = invalidFilter
				return fields
			},
		},
		{
			desc: "invalid UserSearchFilter",
			fields: func() v3.LdapFields {
				fields := fields
				fields.UserSearchFilter = invalidFilter
				return fields
			},
		},
		{
			desc: "invalid GroupSearchFilter",
			fields: func() v3.LdapFields {
				fields := fields
				fields.GroupSearchFilter = invalidFilter
				return fields
			},
		},
	}

	validator := authconfig.NewValidator()

	for _, provider := range []string{"openldap", "freeipa"} {
		for _, op := range []v1.Operation{v1.Create, v1.Update} {
			for _, test := range tests {
				name := provider + "_" + string(op) + "_" + test.desc
				t.Run(name, func(t *testing.T) {
					fields := fields
					if test.fields != nil {
						fields = test.fields()
					}
					testLdapAdmit(t, validator, provider, op, fields, !test.disabled, test.allowed)
				})
			}
		}
	}
}

func TestValidateActiveDirectoryConfig(t *testing.T) {
	t.Parallel()
	config := v3.ActiveDirectoryConfig{
		Servers:                     []string{"ad.example.com"},
		TLS:                         true,
		Certificate:                 "CERTIFICATE",
		UserSearchAttribute:         "sAMAccountName|sn|givenName",
		UserLoginAttribute:          "sAMAccountName",
		UserObjectClass:             "person",
		UserNameAttribute:           "sAMAccountName",
		UserEnabledAttribute:        "userAccountControl",
		GroupSearchAttribute:        "sAMAccountName",
		GroupObjectClass:            "group",
		GroupNameAttribute:          "name",
		GroupDNAttribute:            "distinguishedName",
		GroupMemberUserAttribute:    "member",
		GroupMemberMappingAttribute: "distinguishedName",
		UserLoginFilter:             "(&(status=active)(canLogin=true))",
		UserSearchFilter:            "(status=active)",
		GroupSearchFilter:           "(depNo=123)",
	}
	config.ObjectMeta.Name = "activedirectory"
	config.Type = "activeDirectoryConfig"
	config.Enabled = true

	invalidAttr := "1foo"     // Leading digit.
	invalidFilter := "cn=foo" // No parentheses.

	tests := []struct {
		desc    string
		config  func() v3.ActiveDirectoryConfig
		allowed bool
	}{
		{
			desc:    "valid config",
			allowed: true,
		},
		{
			desc: "servers not specified",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.Servers = nil
				return config
			},
		},
		{
			desc: "servers not specified for the disabled provider",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.Servers = nil
				config.Enabled = false
				return config
			},
			allowed: true,
		},
		{
			desc: "tls is on without certificate",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.Certificate = ""
				return config
			},
		},
		{
			desc: "invalid UserSearchAttribute",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.UserSearchAttribute = invalidAttr
				return config
			},
		},
		{
			desc: "invalid UserLoginAttribute",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.UserLoginAttribute = invalidAttr
				return config
			},
		},
		{
			desc: "invalid UserObjectClass",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.UserObjectClass = invalidAttr
				return config
			},
		},
		{
			desc: "invalid UserNameAttribute",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.UserNameAttribute = invalidAttr
				return config
			},
		},
		{
			desc: "invalid UserEnabledAttribute",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.UserEnabledAttribute = invalidAttr
				return config
			},
		},
		{
			desc: "invalid GroupSearchAttribute",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.GroupSearchAttribute = invalidAttr
				return config
			},
		},
		{
			desc: "invalid GroupObjectClass",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.GroupObjectClass = invalidAttr
				return config
			},
		},
		{
			desc: "invalid GroupNameAttribute",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.GroupNameAttribute = invalidAttr
				return config
			},
		},
		{
			desc: "invalid GroupDNAttribute",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.GroupDNAttribute = invalidAttr
				return config
			},
		},
		{
			desc: "invalid GroupMemberUserAttribute",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.GroupMemberUserAttribute = invalidAttr
				return config
			},
		},
		{
			desc: "invalid GroupMemberMappingAttribute",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.GroupMemberMappingAttribute = invalidAttr
				return config
			},
		},
		{
			desc: "invalid UserLoginFilter",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.UserLoginFilter = invalidFilter
				return config
			},
		},
		{
			desc: "invalid UserSearchFilter",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.UserSearchFilter = invalidFilter
				return config
			},
		},
		{
			desc: "invalid GroupSearchFilter",
			config: func() v3.ActiveDirectoryConfig {
				config := config
				config.GroupSearchFilter = invalidFilter
				return config
			},
		},
	}

	validator := authconfig.NewValidator()

	for _, op := range []v1.Operation{v1.Create, v1.Update} {
		for _, test := range tests {
			name := string(op) + "_" + test.desc
			t.Run(name, func(t *testing.T) {
				config := config
				if test.config != nil {
					config = test.config()
				}
				testActiveDirectoryAdmit(t, validator, op, config, test.allowed)
			})
		}
	}
}

func TestIsValidLdapAttr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		attr  string
		valid bool
	}{
		{"", false},
		// Short names.
		{"a", true},
		{"a1", true},
		{"a1-", true},
		{"a-b", true},
		{"a1-b2", true},
		{"1a", false},
		{"-a", false},
		{"-1a", false},
		{"1-a", false},
		// Numeric OIDs.
		{"0", true},
		{"1", true},
		{"0.1", true},
		{"1.2", true},
		{"0.0.0", true},
		{"1.2.3", true},
		{"123.456.789", true},
		{"12345678901234567890", true},
		{"1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20", true},
		{".", false},
		{"1.", false},
		{"1..1", false},
		{"1.-1", false},
		{"01", false},
		{"1.02", false},
	}

	for _, test := range tests {
		t.Run(test.attr, func(t *testing.T) {
			assert.Equal(t, test.valid, authconfig.IsValidLdapAttr(test.attr))
		})
	}
}

func testLdapAdmit(t *testing.T, validator *authconfig.Validator, provider string, op v1.Operation, fields v3.LdapFields, enabled, allowed bool) {
	var oldConfig, newConfig any
	switch provider {
	case "openldap":
		o := v3.OpenLdapConfig{}
		o.ObjectMeta.Name = provider
		o.Type = "openLdapConfig"
		n := o
		n.LdapFields = fields
		n.Enabled = enabled
		oldConfig, newConfig = o, n
	case "freeipa":
		o := v3.OpenLdapConfig{}
		o.ObjectMeta.Name = provider
		o.Type = "freeIpaConfig"
		n := o
		n.LdapFields = fields
		n.Enabled = enabled
		oldConfig, newConfig = o, n
	}

	testAdmit(t, validator, op, oldConfig, newConfig, allowed)
}

func testActiveDirectoryAdmit(t *testing.T, validator *authconfig.Validator, op v1.Operation, newConfig v3.ActiveDirectoryConfig, allowed bool) {
	oldConfig := v3.ActiveDirectoryConfig{}
	oldConfig.Name = newConfig.Name
	oldConfig.Type = newConfig.Type
	testAdmit(t, validator, op, oldConfig, newConfig, allowed)
}

func testAdmit(t *testing.T, validator *authconfig.Validator, op v1.Operation, oldConfig, newConfig any, allowed bool) {
	oldObjRaw, err := json.Marshal(&oldConfig)
	require.NoError(t, err, "failed to marshal old AuthConfig")

	objRaw, err := json.Marshal(&newConfig)
	require.NoError(t, err, "failed to marshal AuthConfig")

	resp, err := validator.Admitters()[0].Admit(newRequest(op, objRaw, oldObjRaw))
	require.NoError(t, err)
	assert.Equal(t, allowed, resp.Allowed)
	if allowed != resp.Allowed {
		t.Log(resp.Result.Message)
	}
}

func newRequest(op v1.Operation, obj, oldObj []byte) *admission.Request {
	return &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       op,
			Object:          runtime.RawExtension{Raw: obj},
			OldObject:       runtime.RawExtension{Raw: oldObj},
		},
		Context: context.Background(),
	}
}
