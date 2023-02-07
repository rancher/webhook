// Package podsecurityadmission contains utility functions for managing PodSecurity-related resources
package podsecurityadmission

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blang/semver"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	psav1 "k8s.io/pod-security-admission/admission/api/v1"
	psav1beta1 "k8s.io/pod-security-admission/admission/api/v1beta1"
	"sigs.k8s.io/yaml"
)

var (
	parsedRangeAtLeast125 = semver.MustParseRange(">= 1.25.0-rancher0")
	parsedRange123to124   = semver.MustParseRange(">=1.23.0-rancher0 <=1.24.99-rancher-0")
)

// GetAdmissionConfigFromCluster generates an AdmissionConfiguration from a Cluster,
// or a one with default values if the cluster does not have one.
func GetAdmissionConfigFromCluster(cluster *apisv3.Cluster) *apiserverv1.AdmissionConfiguration {
	if cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.AdmissionConfiguration == nil {
		return &apiserverv1.AdmissionConfiguration{
			TypeMeta: metav1.TypeMeta{
				APIVersion: apiserverv1.SchemeGroupVersion.String(),
				Kind:       "AdmissionConfiguration",
			},
		}
	}
	return cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.AdmissionConfiguration.DeepCopy()
}

// GetPluginConfigFromTemplate generates a PluginConfig for PodSecurity from a PodSecurityAdmissionConfigurationTemplate.
func GetPluginConfigFromTemplate(template *apisv3.PodSecurityAdmissionConfigurationTemplate, k8sVersion string) (apiserverv1.AdmissionPluginConfiguration, error) {
	plugin := apiserverv1.AdmissionPluginConfiguration{
		Name: "PodSecurity",
		Configuration: &runtime.Unknown{
			ContentType: "application/json",
		},
	}
	parsedVersion, err := GetClusterVersion(k8sVersion)
	if err != nil {
		return plugin, fmt.Errorf("failed to parse cluster version: %w", err)
	}
	var psaConfig runtime.Object
	switch {
	case parsedRangeAtLeast125(parsedVersion):
		psaConfig = &psav1.PodSecurityConfiguration{
			TypeMeta: metav1.TypeMeta{
				APIVersion: psav1.SchemeGroupVersion.String(),
				Kind:       "PodSecurityConfiguration",
			},
		}
	case parsedRange123to124(parsedVersion):
		psaConfig = &psav1beta1.PodSecurityConfiguration{
			TypeMeta: metav1.TypeMeta{
				APIVersion: psav1beta1.SchemeGroupVersion.String(),
				Kind:       "PodSecurityConfiguration",
			},
		}
	}

	// here we use JSON to convert the Configuration under template into an instance of PodSecurityConfiguration
	// it works because those two structs have the same JSON tags
	data, err := json.Marshal(template.Configuration)
	if err != nil {
		return plugin, fmt.Errorf("failed to marshal configuration from template: %w", err)
	}
	if err = json.Unmarshal(data, psaConfig); err != nil {
		return plugin, fmt.Errorf("failed to unmarshal data into PodSecurityConfiguration: %w", err)
	}
	cBytes, err := json.Marshal(psaConfig)
	if err != nil {
		return plugin, fmt.Errorf("failed to marshal PodSecurityConfiguration: %w", err)
	}
	plugin.Configuration.Raw = cBytes
	return plugin, nil
}

// GetPluginConfigFromCluster generates a PluginConfig for PodSecurity from a Cluster,
// or a new one with default values if the cluster does not have one.
// True is returned if a PluginConfig is found in the cluster.
func GetPluginConfigFromCluster(cluster *apisv3.Cluster) (apiserverv1.AdmissionPluginConfiguration, bool) {
	admissionConfig := GetAdmissionConfigFromCluster(cluster)
	for _, item := range admissionConfig.Plugins {
		if item.Name == "PodSecurity" {
			return *item.DeepCopy(), true
		}
	}
	return apiserverv1.AdmissionPluginConfiguration{
		Name: "PodSecurity",
		Configuration: &runtime.Unknown{
			ContentType: "application/json",
		},
	}, false
}

// DropPSAPluginConfigFromAdmissionConfig removes the PluginConfig for PodSecurity from a Cluster if it has one.
func DropPSAPluginConfigFromAdmissionConfig(cluster *apisv3.Cluster) {
	var plugins []apiserverv1.AdmissionPluginConfiguration
	admissionConfig := GetAdmissionConfigFromCluster(cluster)
	for _, item := range admissionConfig.Plugins {
		if item.Name != "PodSecurity" {
			plugins = append(plugins, item)
		}
	}
	cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.AdmissionConfiguration.Plugins = plugins
}

// GetClusterVersion parses and returns a k8s version.
func GetClusterVersion(version string) (semver.Version, error) {
	var parsedVersion semver.Version
	if len(version) <= 1 || !strings.HasPrefix(version, "v") {
		return parsedVersion, fmt.Errorf("%s is not valid k8s version", version)
	}
	parsedVersion, err := semver.Parse(version[1:])
	if err != nil {
		return parsedVersion, fmt.Errorf("%s is not valid semver: %w", version, err)
	}
	return parsedVersion, nil
}

// GenerateAdmissionConfigFile generates the admission configuration file for PodSecurity based on the provided PodSecurityAdmissionConfigurationTemplate.
// The k8sVersion is required for determining the API version.
func GenerateAdmissionConfigFile(configurationTemplate *apisv3.PodSecurityAdmissionConfigurationTemplate, k8sVersion string) ([]byte, error) {
	plugin, err := GetPluginConfigFromTemplate(configurationTemplate, k8sVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get plugin config from template: %w", err)
	}
	config := apiserverv1.AdmissionConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiserverv1.SchemeGroupVersion.String(),
			Kind:       "AdmissionConfiguration",
		},
		Plugins: []apiserverv1.AdmissionPluginConfiguration{
			plugin,
		},
	}
	parsed, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the generated admission configuration: %w", err)
	}
	return parsed, err
}
