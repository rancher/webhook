package common

import (
	"fmt"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

type featureCache interface {
	Get(name string) (*v3.Feature, error)
}

// IsFeatureEnabled checks if a given feature is enabled based on its feature cache entry.
// It returns false if the feature is not found or if any error occurs while retrieving the feature.
func IsFeatureEnabled(featureCache featureCache, featureName string) (bool, error) {
	feature, err := featureCache.Get(featureName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to determine status of '%s' feature: %w", featureName, err)
	}

	enabled := feature.Status.Default
	if feature.Spec.Value != nil {
		enabled = *feature.Spec.Value
	}

	return enabled, nil
}
