package common

import "k8s.io/utils/strings/slices"

const (
	// EnforceLabel is a that governs the PSS that is enforced for a namespace
	EnforceLabel = "pod-security.kubernetes.io/enforce"
	// EnforceVersionLabel is a label  that governs the PSS version that is enforced for a namespace
	EnforceVersionLabel = "pod-security.kubernetes.io/enforce-version"
	// AuditLabel is a label  that governs the PSS that is used for auditing a namespace
	AuditLabel = "pod-security.kubernetes.io/audit"
	// AuditVersionLabel is a label  that governs the PSS version that is used for auditing a namespace
	AuditVersionLabel = "pod-security.kubernetes.io/audit-version"
	// WarnLabel is a label  that governs the PSS that is used for warning about PSA violations in a namespace
	WarnLabel = "pod-security.kubernetes.io/warn"
	// WarnVersionLabel is a label  that governs the PSS version that is used for warning about PSA violations in a namespace
	WarnVersionLabel = "pod-security.kubernetes.io/warn-version"
)

var psaLabels = []string{
	EnforceLabel, EnforceVersionLabel, AuditLabel, AuditVersionLabel, WarnLabel, WarnVersionLabel,
}

// IsUpdatingPSAConfig will indicate whether or not the labels being passed in
// are attempting to update PSA-related configuration.
func IsUpdatingPSAConfig(old, new map[string]string) bool {
	for _, label := range psaLabels {
		if old[label] != new[label] {
			return true
		}
	}
	return false
}

// IsCreatingPSAConfig will indicate whether or not the labels being passed in
// are attempting to create PSA-related configuration.
func IsCreatingPSAConfig(new map[string]string) bool {
	for label := range new {
		if slices.Contains(psaLabels, label) {
			return true
		}
	}
	return false
}
