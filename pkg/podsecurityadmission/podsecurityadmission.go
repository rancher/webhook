// Package podsecurityadmission contains utility functions for managing PodSecurity-related resources
package podsecurityadmission

import (
	"encoding/json"
	"fmt"

	"net/http"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	psav1 "k8s.io/pod-security-admission/admission/api/v1"
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

// GetPluginConfigFromTemplate generates a PluginConfig for PodSecurity from a PodSecurityAdmissionConfigurationTemplate
func GetPluginConfigFromTemplate(template *apisv3.PodSecurityAdmissionConfigurationTemplate) (apiserverv1.AdmissionPluginConfiguration, error) {
	plugin := apiserverv1.AdmissionPluginConfiguration{
		Name: "PodSecurity",
		Configuration: &runtime.Unknown{
			ContentType: "application/json",
		},
	}
	psaConfig := psav1.PodSecurityConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: psav1.SchemeGroupVersion.String(),
			Kind:       "PodSecurityConfiguration",
		},
	}

	// here we use JSON to convert the Configuration under template into an instance of PodSecurityConfiguration
	// it works because those two structs have the same JSON tags
	data, err := json.Marshal(template.Configuration)
	if err != nil {
		return plugin, fmt.Errorf("failed to marshal configuration from template: %w", err)
	}
	if err = json.Unmarshal(data, &psaConfig); err != nil {
		return plugin, fmt.Errorf("failed to unmarshal data into PodSecurityConfiguration: %w", err)
	}
	cBytes, err := json.Marshal(psaConfig)
	if err != nil {
		return plugin, fmt.Errorf("failed to marshal PodSecurityConfiguration: %w", err)
	}
	plugin.Configuration.Raw = cBytes
	return plugin, nil
}

// GetPlugConfigFromCluster generates a PluginConfig for PodSecurity from a Cluster,
// or a new one with default values if the cluster does not have one.
// True is returned if a PluginConfig is found in the cluster.
func GetPlugConfigFromCluster(cluster *apisv3.Cluster) (apiserverv1.AdmissionPluginConfiguration, bool) {
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

// DropPSAPlugConfigFromAdmissionConfig removes the PluginConfig for PodSecurity from a Cluster if it has one.
func DropPSAPlugConfigFromAdmissionConfig(cluster *apisv3.Cluster) {
	var plugins []apiserverv1.AdmissionPluginConfiguration
	admissionConfig := GetAdmissionConfigFromCluster(cluster)
	for _, item := range admissionConfig.Plugins {
		if item.Name != "PodSecurity" {
			plugins = append(plugins, item)
		}
	}
	cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.AdmissionConfiguration.Plugins = plugins
	return
}

// AdmissionResponseAllowed returns a minimal AdmissionResponse in which Allowed is true
func AdmissionResponseAllowed() *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: true,
	}
}

// AdmissionResponseBadRequest returns an AdmissionResponse for BadRequest(err code 400)
// the message is used as the message in the response
func AdmissionResponseBadRequest(message string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Result: &metav1.Status{
			Status:  "Failure",
			Message: message,
			Reason:  metav1.StatusReasonBadRequest,
			Code:    http.StatusBadRequest,
		},
		Allowed: false,
	}
}
