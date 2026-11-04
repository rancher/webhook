package common

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/validate/content"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// PDB holds PodDisruptionBudget string fields, decoupled from API-group-specific types.
type PDB struct {
	MinAvailable   string
	MaxUnavailable string
}

// ValidateWebhookDeploymentCustomization validates the fields of a webhook deployment
// customization spec using standard k8s types.
func ValidateWebhookDeploymentCustomization(replicaCount *int32, tolerations []corev1.Toleration, affinity *corev1.Affinity, pdb *PDB, path *field.Path) field.ErrorList {
	var errList field.ErrorList

	if replicaCount != nil && *replicaCount < 1 {
		errList = append(errList, field.Invalid(path.Child("replicaCount"), *replicaCount, "must be at least 1"))
	}

	errList = append(errList, ValidateAppendTolerations(tolerations, path.Child("appendTolerations"))...)
	errList = append(errList, ValidateAffinity(affinity, path.Child("overrideAffinity"))...)
	errList = append(errList, ValidatePDB(pdb, path.Child("podDisruptionBudget"))...)

	return errList
}

// ValidatePDB validates PodDisruptionBudget minAvailable/maxUnavailable values.
func ValidatePDB(pdb *PDB, path *field.Path) field.ErrorList {
	if pdb == nil {
		return nil
	}
	var errList field.ErrorList

	minAvailStr := pdb.MinAvailable
	maxUnavailStr := pdb.MaxUnavailable

	if (minAvailStr == "" && maxUnavailStr == "") ||
		(minAvailStr == "0" && maxUnavailStr == "0") ||
		(minAvailStr != "" && minAvailStr != "0") && (maxUnavailStr != "" && maxUnavailStr != "0") {
		errList = append(errList, field.Invalid(path, pdb, "both minAvailable and maxUnavailable cannot be set to a non-zero value, at least one must be omitted or set to zero"))
		return errList
	}

	if minAvailStr != "" {
		minAvailInt, err := strconv.Atoi(minAvailStr)
		if err != nil {
			if !PdbPercentageRegex.MatchString(minAvailStr) {
				errList = append(errList, field.Invalid(path.Child("minAvailable"), minAvailStr,
					fmt.Sprintf("must be a non-negative whole integer or a percentage value between 0 and 100, regex used is '%s'", PdbPercentageRegex.String())))
			}
		} else if minAvailInt < 0 {
			errList = append(errList, field.Invalid(path.Child("minAvailable"), minAvailStr, "cannot be a negative integer"))
		}
	}

	if maxUnavailStr != "" {
		maxUnavailInt, err := strconv.Atoi(maxUnavailStr)
		if err != nil {
			if !PdbPercentageRegex.MatchString(maxUnavailStr) {
				errList = append(errList, field.Invalid(path.Child("maxUnavailable"), maxUnavailStr,
					fmt.Sprintf("must be a non-negative whole integer or a percentage value between 0 and 100, regex used is '%s'", PdbPercentageRegex.String())))
			}
		} else if maxUnavailInt < 0 {
			errList = append(errList, field.Invalid(path.Child("maxUnavailable"), maxUnavailStr, "cannot be a negative integer"))
		}
	}

	return errList
}

// ValidateAppendTolerations validates that toleration keys, values, and operators follow K8s rules.
func ValidateAppendTolerations(tolerations []corev1.Toleration, path *field.Path) field.ErrorList {
	var errList field.ErrorList

	validOperators := []string{
		string(""), // defaults to Equal
		string(corev1.TolerationOpEqual),
		string(corev1.TolerationOpExists),
		// Ops below require below the "TaintTolerationComparisonOperators" feature gate in the target cluster
		string(corev1.TolerationOpGt),
		string(corev1.TolerationOpLt),
	}

	for k, s := range tolerations {
		idxPath := path.Index(k)

		// Validate Operator
		isValidOp := slices.Contains(validOperators, string(s.Operator))

		if !isValidOp {
			errList = append(errList, field.NotSupported(idxPath.Child("operator"), s.Operator, validOperators))
		}

		//  Validate Key
		errList = append(errList, validation.ValidateLabelName(s.Key, idxPath.Child("key"))...)

		// Validate Value
		if s.Operator == corev1.TolerationOpExists {
			if len(s.Value) > 0 {
				errList = append(errList, field.Invalid(idxPath.Child("value"), s.Value, "value must be empty when operator is Exists"))
			}
		} else if len(s.Value) > 0 {
			// the value can be empty, but if it is defined, it need to be validated.
			for _, msg := range content.IsLabelValue(s.Value) {
				errList = append(errList, field.Invalid(idxPath.Child("value"), s.Value, msg))
			}
		}
	}
	return errList
}

// ValidateAffinity validates an Affinity spec including node, pod, and pod anti-affinity rules.
func ValidateAffinity(overrideAffinity *corev1.Affinity, path *field.Path) field.ErrorList {
	if overrideAffinity == nil {
		return nil
	}
	var errList field.ErrorList

	if affinity := overrideAffinity.NodeAffinity; affinity != nil {
		errList = append(errList,
			validatePreferredSchedulingTerms(affinity.PreferredDuringSchedulingIgnoredDuringExecution,
				path.Child("nodeAffinity").Child("preferredDuringSchedulingIgnoredDuringExecution"))...,
		)
		errList = append(errList,
			validateNodeSelector(affinity.RequiredDuringSchedulingIgnoredDuringExecution,
				path.Child("nodeAffinity").Child("requiredDuringSchedulingIgnoredDuringExecution"))...,
		)
	}

	if podAffinity := overrideAffinity.PodAffinity; podAffinity != nil {
		errList = append(errList, validatePodAffinityTerms(podAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
			path.Child("podAffinity").Child("requiredDuringSchedulingIgnoredDuringExecution"))...)

		errList = append(errList, validateWeightedPodAffinityTerms(podAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
			path.Child("podAffinity").Child("preferredDuringSchedulingIgnoredDuringExecution"))...)
	}

	if podAntiAffinity := overrideAffinity.PodAntiAffinity; podAntiAffinity != nil {
		errList = append(errList, validatePodAffinityTerms(podAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
			path.Child("podAntiAffinity").Child("requiredDuringSchedulingIgnoredDuringExecution"))...)

		errList = append(errList, validateWeightedPodAffinityTerms(podAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
			path.Child("podAntiAffinity").Child("preferredDuringSchedulingIgnoredDuringExecution"))...)
	}
	return errList
}

// ErrorListToStatus converts a field.ErrorList to a metav1.Status with bullet-pointed messages.
func ErrorListToStatus(errList field.ErrorList) *metav1.Status {
	if len(errList) == 0 {
		return nil
	}
	var builder strings.Builder
	builder.WriteString("* ")
	for i, fieldErr := range errList {
		builder.WriteString(fieldErr.Error())
		if i != len(errList)-1 {
			builder.WriteString("\n* ")
		}
	}
	return &metav1.Status{
		Status:  "Failure",
		Message: builder.String(),
		Reason:  metav1.StatusReasonInvalid,
		Code:    http.StatusUnprocessableEntity,
	}
}

func validatePodAffinityTerms(terms []corev1.PodAffinityTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	for k, v := range terms {
		errList = append(errList, validatePodAffinityTerm(v, path.Index(k))...)
	}
	return errList
}

func validateWeightedPodAffinityTerms(terms []corev1.WeightedPodAffinityTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	for k, v := range terms {
		errList = append(errList, validatePodAffinityTerm(v.PodAffinityTerm, path.Index(k).Child("podAffinityTerm"))...)
	}
	return errList
}

func validatePodAffinityTerm(term corev1.PodAffinityTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	errList = append(errList, validateLabelSelector(term.LabelSelector, path.Child("labelSelector"))...)
	errList = append(errList, validateLabelSelector(term.NamespaceSelector, path.Child("namespaceSelector"))...)
	return errList
}

func validateLabelSelector(labelSelector *metav1.LabelSelector, path *field.Path) field.ErrorList {
	return validation.ValidateLabelSelector(labelSelector, validation.LabelSelectorValidationOptions{}, path)
}

func validatePreferredSchedulingTerms(terms []corev1.PreferredSchedulingTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	for k, v := range terms {
		errList = append(errList, validateNodeSelectorTerm(v.Preference, path.Index(k).Child("preferences"))...)
	}
	return errList
}

func validateNodeSelector(nodeSelector *corev1.NodeSelector, path *field.Path) field.ErrorList {
	if nodeSelector == nil {
		return nil
	}
	var errList field.ErrorList
	nodeSelectorPath := path.Child("nodeSelectorTerms")
	for k, v := range nodeSelector.NodeSelectorTerms {
		errList = append(errList, validateNodeSelectorTerm(v, nodeSelectorPath.Index(k))...)
	}
	return errList
}

func validateNodeSelectorTerm(term corev1.NodeSelectorTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	errList = append(errList, validateNodeSelectorRequirements(term.MatchFields, path.Child("matchFields"))...)
	errList = append(errList, validateNodeSelectorRequirements(term.MatchExpressions, path.Child("matchExpressions"))...)
	return errList
}

func validateNodeSelectorRequirements(selector []corev1.NodeSelectorRequirement, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	for k, s := range selector {
		errList = append(errList, validation.ValidateLabelName(s.Key, path.Index(k).Child("key"))...)
	}
	return errList
}
