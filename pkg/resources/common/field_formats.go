package common

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// maxDisplayNameLength is the maximum number of characters allowed in a cluster display name.
const maxDisplayNameLength = 253

// registryHostRegex matches a registry host, which is either a host name or IP address, or an IPv6 address in square
// brackets, optionally followed by a port. The port range is checked separately.
var registryHostRegex = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(:[0-9]+)?$`)

// registryPathSegmentRegex matches one segment of the path that can follow the host of a registry config key.
var registryPathSegmentRegex = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ValidateDisplayName ensures that a cluster display name has at most 253 characters, and contains no control
// characters, line or paragraph separators, quotes, or backslashes. Rancher writes the display name into YAML and
// kubeconfig files. Spaces and Unicode letters are allowed.
// name is the print friendly name of the field.
func ValidateDisplayName(displayName, name string) *admissionv1.AdmissionResponse {
	if displayName == "" {
		return admission.ResponseAllowed()
	}
	if utf8.RuneCountInString(displayName) > maxDisplayNameLength {
		return admission.ResponseBadRequest(
			fmt.Sprintf("%s cannot be longer than %d characters", name, maxDisplayNameLength))
	}
	if strings.ContainsFunc(displayName, func(r rune) bool {
		// U+2028 and U+2029 are not control characters, but some YAML parsers treat them as line breaks.
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r == '"' || r == '\'' || r == '\\'
	}) {
		return admission.ResponseBadRequest(
			fmt.Sprintf("%s cannot contain control characters, line breaks, quotes, or backslashes", name))
	}

	return admission.ResponseAllowed()
}

// ValidateFQDN ensures that a fully qualified domain name is a valid RFC 1123 subdomain, optionally followed by a port
// in the form of "host:port". Rancher builds the URL of the endpoint as "https://" plus this value, so a port is valid.
// An empty value is allowed. DNS names are case-insensitive, so upper case letters are allowed.
// name is the print friendly name of the field.
func ValidateFQDN(fqdn, name string) *admissionv1.AdmissionResponse {
	if fqdn == "" {
		return admission.ResponseAllowed()
	}
	host := strings.ToLower(fqdn)
	if i := strings.LastIndex(host, ":"); i >= 0 {
		if port, err := strconv.ParseUint(host[i+1:], 10, 16); err != nil || port == 0 {
			return admission.ResponseBadRequest(
				fmt.Sprintf("%s must have a port between 1 and 65535 after the colon", name))
		}
		host = host[:i]
	}
	if errs := validation.IsDNS1123Subdomain(host); len(errs) > 0 {
		return admission.ResponseBadRequest(
			fmt.Sprintf("%s must be a valid DNS name with an optional port: %s", name, strings.Join(errs, "; ")))
	}
	// IsDNS1123Subdomain does not limit the length of a single label
	for _, label := range strings.Split(host, ".") {
		if len(label) > validation.DNS1123LabelMaxLength {
			return admission.ResponseBadRequest(
				fmt.Sprintf("%s must be a valid DNS name with an optional port: each label must be no more than %d characters", name, validation.DNS1123LabelMaxLength))
		}
	}

	return admission.ResponseAllowed()
}

// agentEnvVarNameRegex matches a valid name of an agent environment variable. Rancher skips other names when it renders
// the registration commands and the Windows install script. The "$env:" prefix is allowed because Rancher removes it
// for Windows nodes.
var agentEnvVarNameRegex = regexp.MustCompile(`^(\$env:)?[a-zA-Z_][a-zA-Z0-9_]*$`)

// ValidateAgentEnvVarNames validates every name of newNames that is not a name of oldNames. Names that already exist
// are not validated, so existing clusters with an invalid name can still be updated. oldNames is nil on create.
// name is the print friendly name of the field.
func ValidateAgentEnvVarNames(oldNames, newNames []string, name string) *admissionv1.AdmissionResponse {
	for _, envVarName := range newNames {
		if slices.Contains(oldNames, envVarName) {
			continue
		}
		if !agentEnvVarNameRegex.MatchString(envVarName) {
			return admission.ResponseBadRequest(
				fmt.Sprintf("%s has an invalid environment variable name %q: the name must start with a letter or '_' and contain only letters, digits, and '_'", name, envVarName))
		}
	}

	return admission.ResponseAllowed()
}

// ValidateRegistryConfigKeys validates every key of newConfigs that is not a key of oldConfigs with
// ValidateRegistryConfigKey. Keys that already exist are not validated, so existing objects with an invalid key can
// still be updated. oldConfigs is nil on create.
func ValidateRegistryConfigKeys[V any](oldConfigs, newConfigs map[string]V) *admissionv1.AdmissionResponse {
	for _, key := range slices.Sorted(maps.Keys(newConfigs)) {
		if _, ok := oldConfigs[key]; ok {
			continue
		}
		if response := ValidateRegistryConfigKey(key); !response.Allowed {
			return response
		}
	}

	return admission.ResponseAllowed()
}

// ValidateRegistryConfigKey ensures that a key of the registry configs is a registry host in the form of "host" or
// "host:port", optionally followed by a path such as "host/project". Rancher accepts such a path, because the key
// stays inside of the TLS directory of the registries. The key does not contain whitespace, control characters, a
// leading "/", or a path segment of "." or "..", because Rancher uses the key as part of a file path.
func ValidateRegistryConfigKey(key string) *admissionv1.AdmissionResponse {
	if key == "" {
		return admission.ResponseBadRequest("registry config key cannot be empty")
	}
	if strings.ContainsFunc(key, func(r rune) bool { return !unicode.IsPrint(r) || r == ' ' }) {
		return admission.ResponseBadRequest(
			fmt.Sprintf("registry config key %q cannot contain whitespace or control characters", key))
	}
	if strings.HasPrefix(key, "/") {
		return admission.ResponseBadRequest(
			fmt.Sprintf("registry config key %q cannot start with '/'", key))
	}
	if strings.Contains(key, "..") {
		return admission.ResponseBadRequest(
			fmt.Sprintf("registry config key %q cannot contain '..'", key))
	}

	host, path, hasPath := strings.Cut(key, "/")
	if !registryHostRegex.MatchString(host) {
		return admission.ResponseBadRequest(
			fmt.Sprintf("registry config key %q must be a registry host in the form of \"host\" or \"host:port\", optionally followed by a path", key))
	}
	// the port is the part after the last colon, outside of the brackets of an IPv6 address
	if i := strings.LastIndex(host, ":"); i > strings.LastIndex(host, "]") {
		if port, err := strconv.Atoi(host[i+1:]); err != nil || port < 1 || port > 65535 {
			return admission.ResponseBadRequest(
				fmt.Sprintf("registry config key %q must have a port between 1 and 65535", key))
		}
	}
	if hasPath {
		for _, segment := range strings.Split(path, "/") {
			if segment == "." || !registryPathSegmentRegex.MatchString(segment) {
				return admission.ResponseBadRequest(
					fmt.Sprintf("registry config key %q must have a path of non-empty segments that contain only letters, digits, '.', '_', and '-'", key))
			}
		}
	}

	return admission.ResponseAllowed()
}
