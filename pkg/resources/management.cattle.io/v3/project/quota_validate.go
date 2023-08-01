package project

import (
	mgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/data/convert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	quotav1 "k8s.io/apiserver/pkg/quota/v1"
)

// quotaFits checks whether the quota in the second argument is sufficient for the requested quota in the first argument.
// If it is not sufficient, a list of the resources that exceed the allotment is returned.
// The ResourceList to be checked can be compiled by passing a
// ResourceQuotaLimit to convertLimitToResourceList before calling this
// function on the result.
func quotaFits(resourceListA corev1.ResourceList, resourceListB corev1.ResourceList) (bool, corev1.ResourceList) {
	_, exceeded := quotav1.LessThanOrEqual(resourceListA, resourceListB)
	// Include resources with negative values among exceeded resources.
	exceeded = append(exceeded, quotav1.IsNegative(resourceListA)...)
	if len(exceeded) == 0 {
		return true, nil
	}
	failedHard := quotav1.Mask(resourceListA, exceeded)
	return false, failedHard
}

// convertLimitToResourceList converts a management.cattle.io/v3 ResourceQuotaLimit object to a core/v1 ResourceList,
// which can then be used to compare quotas.
func convertLimitToResourceList(limit *mgmtv3.ResourceQuotaLimit) (corev1.ResourceList, error) {
	toReturn := corev1.ResourceList{}
	converted, err := convert.EncodeToMap(limit)
	if err != nil {
		return nil, err
	}
	for key, value := range converted {
		q, err := resource.ParseQuantity(convert.ToString(value))
		if err != nil {
			return nil, err
		}
		toReturn[corev1.ResourceName(key)] = q
	}
	return toReturn, nil
}
