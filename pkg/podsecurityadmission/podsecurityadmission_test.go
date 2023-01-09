package podsecurityadmission

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rke/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	v1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	psav1 "k8s.io/pod-security-admission/admission/api/v1"
	psav1beta1 "k8s.io/pod-security-admission/admission/api/v1beta1"
)

func TestGetAdmissionConfigFromCluster(t *testing.T) {
	tests := []struct {
		testName string
		source   *v3.Cluster
		expected *v1.AdmissionConfiguration
	}{
		{
			testName: "cluster with Admission Config",
			source:   getClusterWithAdmissionConfig(),
			expected: getAdmissionPluginConfiguration(),
		},
		{
			testName: "cluster without Admission Config",
			source:   getClusterBasic(),
			expected: &v1.AdmissionConfiguration{
				TypeMeta: metav1.TypeMeta{
					APIVersion: v1.SchemeGroupVersion.String(),
					Kind:       "AdmissionConfiguration",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			output := GetAdmissionConfigFromCluster(tt.source)
			if !reflect.DeepEqual(output, tt.expected) {
				t.Errorf("failed in the test case: [%v]; get: [%v], expected: [%v]", tt.testName, output, tt.expected)
			}
		})
	}
}

func TestGetPluginConfigFromTemplate(t *testing.T) {
	tests := []struct {
		testName       string
		source         *v3.PodSecurityAdmissionConfigurationTemplate
		clusterVersion string
		expected       v1.AdmissionPluginConfiguration
	}{
		{
			testName:       "PSACT Restricted in k8s v1.23",
			source:         getPsactRestricted(),
			clusterVersion: "v1.23.14-rancher1-1",
			expected:       getApcRestrictedPSAv1beta1(),
		},
		{
			testName:       "PSACT Restricted in k8s v1.24",
			source:         getPsactRestricted(),
			clusterVersion: "v1.24.8-rancher1-1",
			expected:       getApcRestrictedPSAv1beta1(),
		},
		{
			testName:       "PSACT Restricted in k8s v1.25",
			source:         getPsactRestricted(),
			clusterVersion: "v1.25.5-rancher1-1",
			expected:       getApcRestrictedPSAv1(),
		},
		{
			testName:       "PSACT Restricted - invalid version",
			source:         getPsactRestricted(),
			clusterVersion: "invalid.b-c",
			expected:       getApcBasic(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			output, err := GetPluginConfigFromTemplate(tt.source, tt.clusterVersion)
			if err != nil && !strings.Contains(err.Error(), "failed to parse cluster version") {
				t.Errorf("failed to invoke GetPluginConfigFromTemplate: %v", err)
			}
			if !reflect.DeepEqual(output, tt.expected) {
				t.Errorf("failed in the test case: [%v]; get: [%v], expected: [%v]", tt.testName, output, tt.expected)
			}
		})
	}
}

func TestGetPluginConfigFromCluster(t *testing.T) {
	clusterNoPluginConfigPodSecurity := getClusterBasic()
	clusterNoPluginConfigPodSecurity.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.AdmissionConfiguration =
		&v1.AdmissionConfiguration{
			TypeMeta: metav1.TypeMeta{
				APIVersion: v1.SchemeGroupVersion.String(),
				Kind:       "AdmissionConfiguration",
			},
			Plugins: []v1.AdmissionPluginConfiguration{
				{
					Name: "EventRateLimit",
				},
			},
		}
	tests := []struct {
		testName    string
		source      *v3.Cluster
		expected    v1.AdmissionPluginConfiguration
		expectFound bool
	}{
		{
			testName:    "Cluster with AdmissionConfig for PodSecurity",
			source:      getClusterWithAdmissionConfig(),
			expected:    getAdmissionPluginConfigurationRestricted(),
			expectFound: true,
		},
		{
			testName:    "Cluster with AdmissionConfig but not for PodSecurity",
			source:      clusterNoPluginConfigPodSecurity,
			expected:    getApcBasic(),
			expectFound: false,
		},
		{
			testName:    "Cluster without AdmissionConfig",
			source:      getClusterBasic(),
			expected:    getApcBasic(),
			expectFound: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			output, found := GetPluginConfigFromCluster(tt.source)
			if found != tt.expectFound {
				t.Errorf("failed in the test case: [%v]; get: [%v], expected: [%v]", tt.testName, found, tt.expectFound)
			}
			if !reflect.DeepEqual(output, tt.expected) {
				t.Errorf("failed in the test case: [%v]; get: [%v], expected: [%v]", tt.testName, output, tt.expected)
			}
		})
	}
}

func getClusterBasic() *v3.Cluster {
	return &v3.Cluster{
		Spec: v3.ClusterSpec{
			ClusterSpecBase: v3.ClusterSpecBase{
				RancherKubernetesEngineConfig: &types.RancherKubernetesEngineConfig{
					Services: types.RKEConfigServices{
						KubeAPI: types.KubeAPIService{},
					},
				},
			},
		},
	}
}

func getClusterWithAdmissionConfig() *v3.Cluster {
	cluster := getClusterBasic()
	cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.AdmissionConfiguration = getAdmissionPluginConfiguration()
	return cluster
}

func getAdmissionPluginConfigurationRestricted() v1.AdmissionPluginConfiguration {
	return v1.AdmissionPluginConfiguration{
		Name: "PodSecurity",
		Configuration: &runtime.Unknown{
			Raw:         []byte{102, 97, 108, 99, 111, 110},
			ContentType: "application/json",
		},
	}
}
func getAdmissionPluginConfiguration() *v1.AdmissionConfiguration {
	return &v1.AdmissionConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1.SchemeGroupVersion.String(),
			Kind:       "AdmissionConfiguration",
		},
		Plugins: []v1.AdmissionPluginConfiguration{
			getAdmissionPluginConfigurationRestricted(),
			{
				Name: "EventRateLimit",
			},
		},
	}
}

func getPsactRestricted() *v3.PodSecurityAdmissionConfigurationTemplate {
	return &v3.PodSecurityAdmissionConfigurationTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "restricted",
		},
		Description: "The default restricted pod security admission configuration template",
		Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
			Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
				Enforce:        "restricted",
				EnforceVersion: "latest",
				Audit:          "restricted",
				AuditVersion:   "latest",
				Warn:           "restricted",
				WarnVersion:    "latest",
			},
			Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
				Usernames:      []string{},
				RuntimeClasses: []string{},
				Namespaces:     []string{"ingress-nginx", "kube-system"},
			},
		},
	}
}

func getApcBasic() v1.AdmissionPluginConfiguration {
	return v1.AdmissionPluginConfiguration{
		Name: "PodSecurity",
		Configuration: &runtime.Unknown{
			ContentType: "application/json",
		},
	}
}

func getApcRestrictedPSAv1() v1.AdmissionPluginConfiguration {
	psaConfig := psav1.PodSecurityConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: psav1.SchemeGroupVersion.String(),
			Kind:       "PodSecurityConfiguration",
		},
		Defaults: psav1.PodSecurityDefaults{
			Enforce:        "restricted",
			EnforceVersion: "latest",
			Audit:          "restricted",
			AuditVersion:   "latest",
			Warn:           "restricted",
			WarnVersion:    "latest",
		},
		Exemptions: psav1.PodSecurityExemptions{
			Usernames:      []string{},
			RuntimeClasses: []string{},
			Namespaces:     []string{"ingress-nginx", "kube-system"},
		},
	}
	cBytes, _ := json.Marshal(psaConfig)
	plugin := getApcBasic()
	plugin.Configuration.Raw = cBytes
	return plugin
}

func getApcRestrictedPSAv1beta1() v1.AdmissionPluginConfiguration {
	psaConfig := psav1beta1.PodSecurityConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: psav1beta1.SchemeGroupVersion.String(),
			Kind:       "PodSecurityConfiguration",
		},
		Defaults: psav1beta1.PodSecurityDefaults{
			Enforce:        "restricted",
			EnforceVersion: "latest",
			Audit:          "restricted",
			AuditVersion:   "latest",
			Warn:           "restricted",
			WarnVersion:    "latest",
		},
		Exemptions: psav1beta1.PodSecurityExemptions{
			Usernames:      []string{},
			RuntimeClasses: []string{},
			Namespaces:     []string{"ingress-nginx", "kube-system"},
		},
	}
	cBytes, _ := json.Marshal(psaConfig)
	plugin := getApcBasic()
	plugin.Configuration.Raw = cBytes
	return plugin
}
