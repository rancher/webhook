package common

import (
	"fmt"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

type featureCache interface {
	Get(name string) (*v3.Feature, error)
}

type settingCache interface {
	Get(name string) (*v3.Setting, error)
}

const (
	// ServerVersionTypeSetting is the name of the Rancher setting that holds
	// the build type, it is "prime" for Prime builds.
	ServerVersionTypeSetting = "server-version-type"
	primeVersionType         = "prime"
)

// IsPrime returns true if Rancher reports itself as a Prime build.
//
// The Feature resources can't be used for this, Rancher sets status.prime on
// Prime-only features in every build.
// It returns false if the setting is not found.
func IsPrime(settingCache settingCache) (bool, error) {
	setting, err := settingCache.Get(ServerVersionTypeSetting)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to determine Rancher version type: %w", err)
	}

	value := setting.Value
	if value == "" {
		value = setting.Default
	}

	return value == primeVersionType, nil
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
