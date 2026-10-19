package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDataDirectoryFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dir      string
		expected bool
	}{
		{
			name:     "empty directory",
			dir:      "",
			expected: true,
		},
		{
			name:     "root directory",
			dir:      "/",
			expected: true,
		},
		{
			name:     "relative",
			dir:      "home",
			expected: false,
		},
		{
			name:     "trailing slash",
			dir:      "/home/",
			expected: false,
		},
		{
			name:     "env var $",
			dir:      "/$HOME",
			expected: false,
		},
		{
			name:     "env var ${}",
			dir:      "/${HOME}",
			expected: false,
		},
		{
			name:     "backtick expr",
			dir:      "/`pwd`",
			expected: false,
		},
		{
			name:     "subshell expr",
			dir:      "/$(pwd)",
			expected: false,
		},
		{
			name:     "current directory leading",
			dir:      "/./tmp",
			expected: false,
		},
		{
			name:     "current directory trailing",
			dir:      "/tmp/.",
			expected: false,
		},
		{
			name:     "parent directory middle",
			dir:      "/tmp/../tmp",
			expected: false,
		},
		{
			name:     "parent directory trailing",
			dir:      "/tmp/..",
			expected: false,
		},
		{
			name:     "shell character pipe",
			dir:      "/tmp/|evil",
			expected: false,
		},
		{
			name:     "shell character semicolon",
			dir:      "/tmp/;evil",
			expected: false,
		},
		{
			name:     "shell character double quote",
			dir:      "/tmp/\"evil",
			expected: false,
		},
		{
			name:     "shell character single quote",
			dir:      "/tmp/'evil",
			expected: false,
		},
		{
			name:     "shell character asterisk",
			dir:      "/tmp/*evil",
			expected: false,
		},
		{
			name:     "shell character question mark",
			dir:      "/tmp/?evil",
			expected: false,
		},
		{
			name:     "shell character hash",
			dir:      "/tmp/#evil",
			expected: false,
		},
		{
			name:     "shell character tilde",
			dir:      "/tmp/~evil",
			expected: false,
		},
		{
			name:     "shell character equals",
			dir:      "/tmp/=evil",
			expected: false,
		},
		{
			name:     "shell character percent",
			dir:      "/tmp/%evil",
			expected: false,
		},
		{
			name:     "shell character ampersand",
			dir:      "/tmp/&evil",
			expected: false,
		},
		{
			name:     "shell character less than",
			dir:      "/tmp/<evil",
			expected: false,
		},
		{
			name:     "shell character greater than",
			dir:      "/tmp/>evil",
			expected: false,
		},
		{
			name:     "shell character curly braces",
			dir:      "/tmp/{evil}",
			expected: false,
		},
		{
			name:     "shell character square brackets",
			dir:      "/tmp/[evil]",
			expected: false,
		},
		{
			name:     "shell character parentheses",
			dir:      "/tmp/(evil)",
			expected: false,
		},
		{
			name:     "newline",
			dir:      "/tmp/x\nchmod 4755 /bin/sh\n/y",
			expected: false,
		},
		{
			name:     "trailing newline",
			dir:      "/tmp/x\n",
			expected: false,
		},
		{
			name:     "carriage return",
			dir:      "/tmp/x\revil",
			expected: false,
		},
		{
			name:     "tab",
			dir:      "/tmp/x\tevil",
			expected: false,
		},
		{
			name:     "space",
			dir:      "/tmp/x /etc",
			expected: false,
		},
		{
			name:     "null byte",
			dir:      "/tmp/x\x00evil",
			expected: false,
		},
		{
			name:     "zero-width space",
			dir:      "/tmp/x\u200bevil",
			expected: false,
		},
		{
			name:     "bidi override",
			dir:      "/tmp/x\u202eevil",
			expected: false,
		},
		{
			name:     "non-breaking space",
			dir:      "/tmp/x\u00a0evil",
			expected: false,
		},
		{
			name:     "line separator",
			dir:      "/tmp/x\u2028evil",
			expected: false,
		},
		{
			name:     "backslash",
			dir:      "/tmp/x\\evil",
			expected: false,
		},
		{
			name:     "valid path with exclamation mark",
			dir:      "/data/a!b",
			expected: true,
		},
		{
			name:     "valid path with non-ASCII letters",
			dir:      "/data/données/数据",
			expected: true,
		},
		{
			name:     "valid path with plus",
			dir:      "/opt/rke2+data",
			expected: true,
		},
		{
			name:     "valid path with at sign",
			dir:      "/data/a@b",
			expected: true,
		},
		{
			name:     "valid path with comma",
			dir:      "/data/a,b",
			expected: true,
		},
		{
			name:     "valid path with colon",
			dir:      "/data/a:b",
			expected: true,
		},
		{
			name:     "valid path with dash underscore and dot",
			dir:      "/data/a-b_c.d",
			expected: true,
		},
		{
			name:     "valid absolute path",
			dir:      "/tmp",
			expected: true,
		},
		{
			name:     "valid deep absolute path",
			dir:      "/var/lib/rancher/rke2",
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response := ValidateDataDirectoryFormat(tt.dir, "Test")
			assert.Equal(t, tt.expected, response.Allowed)
		})
	}
}

func TestValidateDataDirectoryHierarchy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dataDirs map[string]string
		expected bool
	}{
		{
			name: "parent path is root path",
			dataDirs: map[string]string{
				"a": "/",
				"b": "/var/lib/rancher",
			},
			expected: false,
		},
		{
			name: "equal paths",
			dataDirs: map[string]string{
				"a": "/a",
				"b": "/a",
			},
			expected: false,
		},
		{
			name: "nested path child in parent",
			dataDirs: map[string]string{
				"a": "/a",
				"b": "/a/b",
			},
			expected: false,
		},
		{
			name: "nested path parent in child",
			dataDirs: map[string]string{
				"a": "/a/b",
				"b": "/a",
			},
			expected: false,
		},
		{
			name: "distinct paths",
			dataDirs: map[string]string{
				"a": "/a",
				"b": "/b",
				"c": "/c",
			},
			expected: true,
		},
		{
			name: "empty paths ignored",
			dataDirs: map[string]string{
				"a": "/a",
				"b": "",
				"c": "",
			},
			expected: true,
		},
		{
			name: "prefix match but not directory nesting",
			dataDirs: map[string]string{
				"a": "/var/lib/rancher",
				"b": "/var/lib/rancher-other",
			},
			expected: true,
		},
		{
			name: "nested path multiple levels deep",
			dataDirs: map[string]string{
				"a": "/a",
				"b": "/a/b/c/d",
			},
			expected: false,
		},
		{
			name: "one nested pair among distinct directories",
			dataDirs: map[string]string{
				"a": "/a",
				"b": "/b",
				"c": "/a/b",
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response := ValidateDataDirectoryHierarchy(tt.dataDirs)
			assert.Equal(t, tt.expected, response.Allowed)
		})
	}
}
