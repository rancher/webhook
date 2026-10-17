package common

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		displayName string
		expected    bool
	}{
		{name: "empty", displayName: "", expected: true},
		{name: "simple", displayName: "prod-cluster", expected: true},
		{name: "spaces", displayName: "My Production Cluster", expected: true},
		{name: "unicode letters", displayName: "Café Données 数据 クラスタ", expected: true},
		{name: "punctuation", displayName: "team_a (east) #1: v2.0", expected: true},
		{name: "max length", displayName: strings.Repeat("a", 253), expected: true},
		{name: "max length of multibyte characters", displayName: strings.Repeat("数", 253), expected: true},
		{name: "too long", displayName: strings.Repeat("a", 254), expected: false},
		{name: "newline", displayName: "a\nb: c", expected: false},
		{name: "trailing newline", displayName: "a\n", expected: false},
		{name: "carriage return", displayName: "a\rb", expected: false},
		{name: "tab", displayName: "a\tb", expected: false},
		{name: "null byte", displayName: "a\x00b", expected: false},
		{name: "line separator", displayName: "a\u2028b", expected: false},
		{name: "paragraph separator", displayName: "a\u2029b", expected: false},
		{name: "double quote", displayName: `a"b`, expected: false},
		{name: "single quote", displayName: "a'b", expected: false},
		{name: "backslash", displayName: `a\b`, expected: false},
		{name: "traversal is allowed because the display name is not a path", displayName: "../../etc", expected: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response := ValidateDisplayName(tt.displayName, "Display name")
			assert.Equal(t, tt.expected, response.Allowed)
			if !tt.expected {
				assert.Contains(t, response.Result.Message, "Display name")
			}
		})
	}
}

func TestValidateFQDN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fqdn     string
		expected bool
	}{
		{name: "empty", fqdn: "", expected: true},
		{name: "single label", fqdn: "rancher", expected: true},
		{name: "fully qualified", fqdn: "rancher.example.com", expected: true},
		{name: "hyphen and digits", fqdn: "api-1.cluster-2.example.com", expected: true},
		{name: "upper case", fqdn: "Rancher.Example.COM", expected: true},
		{name: "ipv4 address", fqdn: "10.0.0.1", expected: true},
		{name: "max length", fqdn: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), expected: true},
		{name: "too long", fqdn: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62), expected: false},
		{name: "label too long", fqdn: strings.Repeat("a", 64) + ".example.com", expected: false},
		{name: "port", fqdn: "rancher.example.com:6443", expected: true},
		{name: "ipv4 address and port", fqdn: "10.0.0.1:443", expected: true},
		{name: "highest port", fqdn: "rancher.example.com:65535", expected: true},
		{name: "empty port", fqdn: "rancher.example.com:", expected: false},
		{name: "port zero", fqdn: "rancher.example.com:0", expected: false},
		{name: "port too high", fqdn: "rancher.example.com:65536", expected: false},
		{name: "non-numeric port", fqdn: "rancher.example.com:abc", expected: false},
		{name: "signed port", fqdn: "rancher.example.com:+443", expected: false},
		{name: "two ports", fqdn: "rancher.example.com:443:443", expected: false},
		{name: "newline after port", fqdn: "rancher.example.com:443\n", expected: false},
		{name: "port only", fqdn: ":443", expected: false},
		{name: "ipv6 address", fqdn: "[::1]:443", expected: false},
		{name: "newline", fqdn: "rancher.example.com\nevil", expected: false},
		{name: "trailing newline", fqdn: "rancher.example.com\n", expected: false},
		{name: "space", fqdn: "rancher.example.com evil", expected: false},
		{name: "double quote", fqdn: `rancher"example.com`, expected: false},
		{name: "single quote", fqdn: "rancher'example.com", expected: false},
		{name: "backslash", fqdn: `rancher\example.com`, expected: false},
		{name: "traversal", fqdn: "../etc/passwd", expected: false},
		{name: "slash", fqdn: "rancher.example.com/path", expected: false},
		{name: "scheme", fqdn: "https://rancher.example.com", expected: false},
		{name: "underscore", fqdn: "ran_cher.example.com", expected: false},
		{name: "leading hyphen", fqdn: "-rancher.example.com", expected: false},
		{name: "leading dot", fqdn: ".rancher.example.com", expected: false},
		{name: "trailing dot", fqdn: "rancher.example.com.", expected: false},
		{name: "empty label", fqdn: "rancher..example.com", expected: false},
		{name: "wildcard", fqdn: "*.example.com", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response := ValidateFQDN(tt.fqdn, "FQDN")
			assert.Equal(t, tt.expected, response.Allowed)
			if !tt.expected {
				assert.Contains(t, response.Result.Message, "FQDN")
			}
		})
	}
}

func TestValidateRegistryConfigKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{name: "host", key: "registry.example.com", expected: true},
		{name: "single label", key: "localhost", expected: true},
		{name: "docker hub", key: "docker.io", expected: true},
		{name: "host and port", key: "registry.example.com:5000", expected: true},
		{name: "ipv4 and port", key: "10.0.0.1:5000", expected: true},
		{name: "ipv6 in brackets", key: "[::1]", expected: true},
		{name: "ipv6 in brackets and port", key: "[2001:db8::1]:5000", expected: true},
		{name: "underscore", key: "my_registry:5000", expected: true},
		{name: "upper case", key: "Registry.Example.com", expected: true},
		{name: "highest port", key: "registry.example.com:65535", expected: true},
		{name: "empty", key: "", expected: false},
		{name: "traversal", key: "../registry", expected: false},
		{name: "traversal in the middle", key: "registry/../../etc", expected: false},
		{name: "double dot in host", key: "registry..example.com", expected: false},
		{name: "leading slash", key: "/registry.example.com", expected: false},
		{name: "absolute path", key: "/etc/passwd", expected: false},
		{name: "path", key: "registry.example.com/project", expected: true},
		{name: "nested path", key: "registry.example.com/team/project_1", expected: true},
		{name: "port and path", key: "registry.example.com:5000/team", expected: true},
		{name: "path with dots", key: "registry.example.com/team.v1", expected: true},
		{name: "trailing slash", key: "registry.example.com/", expected: false},
		{name: "empty path segment", key: "registry.example.com//team", expected: false},
		{name: "dot path segment", key: "registry.example.com/./team", expected: false},
		{name: "traversal in path", key: "registry.example.com/../../etc", expected: false},
		{name: "space in path", key: "registry.example.com/my team", expected: false},
		{name: "newline in path", key: "registry.example.com/team\nevil", expected: false},
		{name: "backslash in path", key: `registry.example.com/team\evil`, expected: false},
		{name: "colon in path", key: "registry.example.com/team:latest", expected: false},
		{name: "invalid port with path", key: "registry.example.com:abc/team", expected: false},
		{name: "scheme", key: "https://registry.example.com", expected: false},
		{name: "newline", key: "registry.example.com\nevil", expected: false},
		{name: "trailing newline", key: "registry.example.com\n", expected: false},
		{name: "carriage return", key: "registry.example.com\revil", expected: false},
		{name: "tab", key: "registry.example.com\tevil", expected: false},
		{name: "space", key: "registry.example.com evil", expected: false},
		{name: "zero-width space", key: "registry.example.com\u200bevil", expected: false},
		{name: "null byte", key: "registry.example.com\x00evil", expected: false},
		{name: "double quote", key: `registry"example.com`, expected: false},
		{name: "single quote", key: "registry'example.com", expected: false},
		{name: "backslash", key: `registry\example.com`, expected: false},
		{name: "wildcard", key: "*", expected: false},
		{name: "empty port", key: "registry.example.com:", expected: false},
		{name: "non-numeric port", key: "registry.example.com:abc", expected: false},
		{name: "port zero", key: "registry.example.com:0", expected: false},
		{name: "port too high", key: "registry.example.com:65536", expected: false},
		{name: "port too long", key: "registry.example.com:99999999999999999999", expected: false},
		{name: "two ports", key: "registry.example.com:5000:5000", expected: false},
		{name: "leading hyphen", key: "-registry.example.com", expected: false},
		{name: "trailing dot", key: "registry.example.com.", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response := ValidateRegistryConfigKey(tt.key)
			assert.Equal(t, tt.expected, response.Allowed)
		})
	}
}

func TestValidateRegistryConfigKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		oldConfigs map[string]struct{}
		newConfigs map[string]struct{}
		expected   bool
	}{
		{
			name:     "nil configs",
			expected: true,
		},
		{
			name:       "create with valid keys",
			newConfigs: map[string]struct{}{"registry.example.com": {}, "10.0.0.1:5000": {}},
			expected:   true,
		},
		{
			name:       "create with newline",
			newConfigs: map[string]struct{}{"registry.example.com": {}, "evil\nkey": {}},
			expected:   false,
		},
		{
			name:       "create with traversal",
			newConfigs: map[string]struct{}{"../../etc": {}},
			expected:   false,
		},
		{
			name:       "update with unchanged invalid key",
			oldConfigs: map[string]struct{}{"evil\nkey": {}},
			newConfigs: map[string]struct{}{"evil\nkey": {}},
			expected:   true,
		},
		{
			name:       "update with unchanged invalid key and new valid key",
			oldConfigs: map[string]struct{}{"/etc/passwd": {}},
			newConfigs: map[string]struct{}{"/etc/passwd": {}, "registry.example.com": {}},
			expected:   true,
		},
		{
			name:       "update with unchanged invalid key and new invalid key",
			oldConfigs: map[string]struct{}{"/etc/passwd": {}},
			newConfigs: map[string]struct{}{"/etc/passwd": {}, "../other": {}},
			expected:   false,
		},
		{
			name:       "update renames a valid key to an invalid key",
			oldConfigs: map[string]struct{}{"registry.example.com": {}},
			newConfigs: map[string]struct{}{`registry\example.com`: {}},
			expected:   false,
		},
		{
			name:       "update removes an invalid key",
			oldConfigs: map[string]struct{}{"/etc/passwd": {}},
			newConfigs: map[string]struct{}{},
			expected:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response := ValidateRegistryConfigKeys(tt.oldConfigs, tt.newConfigs)
			assert.Equal(t, tt.expected, response.Allowed)
		})
	}
}

// TestValidateRegistryConfigKeyMatchesRancher uses the names of rancher/rancher TestRenderRegistriesTLSFilePath.
// Rancher accepts names that stay inside of the registry TLS directory and rejects the others, so the webhook must
// accept the names that Rancher accepts and reject the names that Rancher rejects.
func TestValidateRegistryConfigKeyMatchesRancher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{name: "host", key: "registry.example.com", expected: true},
		{name: "host and port", key: "registry.example.com:5000", expected: true},
		{name: "path in name stays inside", key: "registry.example.com/team", expected: true},
		{name: "dot dot", key: "..", expected: false},
		{name: "dot dot in the middle", key: "a/../../b", expected: false},
		{name: "dot dot to the data directory", key: "../../../../../../etc/cron.d/x", expected: false},
		{name: "dot", key: ".", expected: false},
		{name: "hostile name with TLS secret", key: "../../../../x", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, ValidateRegistryConfigKey(tt.key).Allowed)
		})
	}
}

func TestValidateAgentEnvVarNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		oldNames []string
		newNames []string
		expected bool
	}{
		{name: "no names", expected: true},
		{name: "valid names", newNames: []string{"HTTP_PROXY", "https_proxy", "_PRIVATE", "CATTLE_AGENT_VAR_DIR", "A1"}, expected: true},
		{name: "windows prefix", newNames: []string{"$env:HTTP_PROXY"}, expected: true},
		{name: "empty name", newNames: []string{""}, expected: false},
		{name: "leading digit", newNames: []string{"1VAR"}, expected: false},
		{name: "hyphen", newNames: []string{"MY-VAR"}, expected: false},
		{name: "dot", newNames: []string{"my.var"}, expected: false},
		{name: "space", newNames: []string{"MY VAR"}, expected: false},
		{name: "equals sign", newNames: []string{"A=B"}, expected: false},
		{name: "newline", newNames: []string{"A\nB"}, expected: false},
		{name: "trailing newline", newNames: []string{"A\n"}, expected: false},
		{name: "command substitution", newNames: []string{"A$(id)"}, expected: false},
		{name: "semicolon", newNames: []string{"A;id"}, expected: false},
		{name: "quote", newNames: []string{`A"B`}, expected: false},
		{name: "backslash", newNames: []string{`A\B`}, expected: false},
		{name: "traversal", newNames: []string{"../x"}, expected: false},
		{name: "prefix only", newNames: []string{"$env:"}, expected: false},
		{name: "double prefix", newNames: []string{"$env:$env:A"}, expected: false},
		{name: "unchanged invalid name", oldNames: []string{"MY-VAR"}, newNames: []string{"MY-VAR"}, expected: true},
		{name: "unchanged invalid name and new valid name", oldNames: []string{"MY-VAR"}, newNames: []string{"MY-VAR", "OK"}, expected: true},
		{name: "unchanged invalid name and new invalid name", oldNames: []string{"MY-VAR"}, newNames: []string{"MY-VAR", "A\nB"}, expected: false},
		{name: "renamed to invalid name", oldNames: []string{"OK"}, newNames: []string{"A B"}, expected: false},
		{name: "invalid name removed", oldNames: []string{"MY-VAR"}, newNames: nil, expected: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response := ValidateAgentEnvVarNames(tt.oldNames, tt.newNames, "spec.agentEnvVars")
			assert.Equal(t, tt.expected, response.Allowed)
			if !tt.expected {
				assert.Contains(t, response.Result.Message, "spec.agentEnvVars")
			}
		})
	}
}
