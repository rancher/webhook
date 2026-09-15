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
		idAttrs  map[string]any // userIDAttribute/groupIDAttribute, set as raw JSON keys.
		disabled bool           // Whether the auth provider is disabled.
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
			allowed: true,
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
			desc:    "valid UserIDAttribute and GroupIDAttribute",
			idAttrs: map[string]any{"userIDAttribute": "uid", "groupIDAttribute": "cn"},
			allowed: true,
		},
		{
			desc:    "invalid UserIDAttribute",
			idAttrs: map[string]any{"userIDAttribute": invalidAttr},
		},
		{
			desc:    "invalid GroupIDAttribute",
			idAttrs: map[string]any{"groupIDAttribute": invalidAttr},
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
					testLdapAdmit(t, validator, provider, op, fields, test.idAttrs, !test.disabled, test.allowed)
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
	config.Name = "activedirectory"
	config.Type = "activeDirectoryConfig"
	config.Enabled = true

	invalidAttr := "1foo"     // Leading digit.
	invalidFilter := "cn=foo" // No parentheses.

	tests := []struct {
		desc    string
		config  func() v3.ActiveDirectoryConfig
		idAttrs map[string]any // userIDAttribute/groupIDAttribute, set as raw JSON keys.
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
			allowed: true,
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
			desc:    "valid UserIDAttribute and GroupIDAttribute",
			idAttrs: map[string]any{"userIDAttribute": "sAMAccountName", "groupIDAttribute": "objectSid"},
			allowed: true,
		},
		{
			desc:    "invalid UserIDAttribute",
			idAttrs: map[string]any{"userIDAttribute": invalidAttr},
		},
		{
			desc:    "invalid GroupIDAttribute",
			idAttrs: map[string]any{"groupIDAttribute": invalidAttr},
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
				testActiveDirectoryAdmit(t, validator, op, config, test.idAttrs, test.allowed)
			})
		}
	}
}

func TestIDAttributeImmutability(t *testing.T) {
	t.Parallel()
	validator := authconfig.NewValidator()

	type state struct {
		enabled bool
		user    string
		group   string
	}

	tests := []struct {
		desc    string
		old     state
		new     state
		allowed bool
	}{
		{
			desc:    "set on first enable",
			old:     state{enabled: false},
			new:     state{enabled: true, user: "uid", group: "cn"},
			allowed: true,
		},
		{
			desc:    "unchanged on enabled provider",
			old:     state{enabled: true, user: "uid", group: "cn"},
			new:     state{enabled: true, user: "uid", group: "cn"},
			allowed: true,
		},
		{
			desc: "user attribute changed on enabled provider",
			old:  state{enabled: true, user: "uid", group: "cn"},
			new:  state{enabled: true, user: "entryUUID", group: "cn"},
		},
		{
			desc: "group attribute changed on enabled provider",
			old:  state{enabled: true, user: "uid", group: "cn"},
			new:  state{enabled: true, user: "uid", group: "gidNumber"},
		},
		{
			desc: "user attribute cleared on enabled provider",
			old:  state{enabled: true, user: "uid", group: "cn"},
			new:  state{enabled: true, group: "cn"},
		},
		{
			desc: "group attribute cleared on enabled provider",
			old:  state{enabled: true, user: "uid", group: "cn"},
			new:  state{enabled: true, user: "uid"},
		},
		{
			desc: "user attribute set on enabled provider",
			old:  state{enabled: true},
			new:  state{enabled: true, user: "uid"},
		},
		{
			desc:    "changed while disabling provider",
			old:     state{enabled: true, user: "uid", group: "cn"},
			new:     state{enabled: false, user: "entryUUID", group: "gidNumber"},
			allowed: true,
		},
		{
			desc:    "changed on disabled provider",
			old:     state{enabled: false, user: "uid", group: "cn"},
			new:     state{enabled: false, user: "entryUUID", group: "gidNumber"},
			allowed: true,
		},
	}

	idAttrs := func(st state) map[string]any {
		attrs := map[string]any{}
		if st.user != "" {
			attrs["userIDAttribute"] = st.user
		}
		if st.group != "" {
			attrs["groupIDAttribute"] = st.group
		}
		return attrs
	}
	// SAML providers with LDAP search keep the attributes under openLdapConfig.
	nestedIDAttrs := func(st state) map[string]any {
		return map[string]any{"openLdapConfig": idAttrs(st)}
	}

	for _, provider := range ldapBasedProviders {
		fields := idAttrs
		if provider.nested {
			fields = nestedIDAttrs
		}
		for _, test := range tests {
			t.Run(provider.name+"_"+test.desc, func(t *testing.T) {
				t.Parallel()
				oldConfig := withFields(t, provider.config(test.old.enabled), fields(test.old))
				newConfig := withFields(t, provider.config(test.new.enabled), fields(test.new))
				// SAML principal IDs come from the assertion, so the LDAP search attributes stay editable.
				allowed := test.allowed || provider.nested
				testAdmit(t, validator, v1.Update, oldConfig, newConfig, allowed)
			})
		}
	}
}

// ldapBasedProviders lists every authconfig type carrying LDAP principal identifier attributes,
// with a minimal config that passes the other validation checks when enabled.
var ldapBasedProviders = []struct {
	name   string
	nested bool
	config func(enabled bool) any
}{
	{"activedirectory", false, func(enabled bool) any {
		c := v3.ActiveDirectoryConfig{Servers: []string{"ad.example.com"}}
		c.Name, c.Type, c.Enabled = "activedirectory", "activeDirectoryConfig", enabled
		return c
	}},
	{"openldap", false, func(enabled bool) any {
		c := v3.OpenLdapConfig{}
		c.Name, c.Type, c.Enabled = "openldap", "openLdapConfig", enabled
		c.Servers = []string{"ldap.example.com"}
		return c
	}},
	{"freeipa", false, func(enabled bool) any {
		c := v3.OpenLdapConfig{}
		c.Name, c.Type, c.Enabled = "freeipa", "freeIpaConfig", enabled
		c.Servers = []string{"ldap.example.com"}
		return c
	}},
	{"shibboleth", true, func(enabled bool) any {
		c := v3.ShibbolethConfig{}
		c.Name, c.Type, c.Enabled = "shibboleth", "shibbolethConfig", enabled
		return c
	}},
	{"okta", true, func(enabled bool) any {
		c := v3.OKTAConfig{}
		c.Name, c.Type, c.Enabled = "okta", "oktaConfig", enabled
		return c
	}},
}

func TestSamlLdapSearchIDAttributes(t *testing.T) {
	t.Parallel()
	validator := authconfig.NewValidator()

	tests := []struct {
		desc    string
		attrs   map[string]any
		enabled bool
		allowed bool
	}{
		{desc: "no ldap search", enabled: true, allowed: true},
		{desc: "valid attributes", attrs: map[string]any{"userIDAttribute": "uid", "groupIDAttribute": "cn"}, enabled: true, allowed: true},
		{desc: "invalid user attribute", attrs: map[string]any{"userIDAttribute": "1foo"}, enabled: true},
		{desc: "invalid group attribute", attrs: map[string]any{"groupIDAttribute": "1foo"}, enabled: true},
		{desc: "invalid attribute on disabled provider", attrs: map[string]any{"userIDAttribute": "1foo"}, allowed: true},
	}

	for _, provider := range ldapBasedProviders {
		if !provider.nested {
			continue
		}
		for _, op := range []v1.Operation{v1.Create, v1.Update} {
			for _, test := range tests {
				t.Run(provider.name+"_"+string(op)+"_"+test.desc, func(t *testing.T) {
					t.Parallel()
					oldConfig := provider.config(false)
					newConfig := provider.config(test.enabled)
					if test.attrs != nil {
						newConfig = withFields(t, newConfig, map[string]any{"openLdapConfig": test.attrs})
					}
					testAdmit(t, validator, op, oldConfig, newConfig, test.allowed)
				})
			}
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

func testLdapAdmit(t *testing.T, validator *authconfig.Validator, provider string, op v1.Operation, fields v3.LdapFields, idAttrs map[string]any, enabled, allowed bool) {
	var oldConfig, newConfig any
	switch provider {
	case "openldap":
		o := v3.OpenLdapConfig{}
		o.Name = provider
		o.Type = "openLdapConfig"
		n := o
		n.LdapFields = fields
		n.Enabled = enabled
		oldConfig, newConfig = o, n
	case "freeipa":
		o := v3.OpenLdapConfig{}
		o.Name = provider
		o.Type = "freeIpaConfig"
		n := o
		n.LdapFields = fields
		n.Enabled = enabled
		oldConfig, newConfig = o, n
	}

	testAdmit(t, validator, op, oldConfig, withFields(t, newConfig, idAttrs), allowed)
}

func testActiveDirectoryAdmit(t *testing.T, validator *authconfig.Validator, op v1.Operation, newConfig v3.ActiveDirectoryConfig, idAttrs map[string]any, allowed bool) {
	oldConfig := v3.ActiveDirectoryConfig{}
	oldConfig.Name = newConfig.Name
	oldConfig.Type = newConfig.Type
	testAdmit(t, validator, op, oldConfig, withFields(t, newConfig, idAttrs), allowed)
}

// withFields marshals config and overlays extra JSON fields. The webhook reads the principal identifier
// attributes from the raw object, so tests set them without depending on the Rancher types carrying them.
func withFields(t *testing.T, config any, extra map[string]any) map[string]any {
	raw, err := json.Marshal(config)
	require.NoError(t, err, "failed to marshal config")

	var obj map[string]any
	require.NoError(t, json.Unmarshal(raw, &obj), "failed to unmarshal config")
	for k, v := range extra {
		obj[k] = v
	}
	return obj
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
