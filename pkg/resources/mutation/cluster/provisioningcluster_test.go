package cluster

import (
	"testing"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_GetKubeAPIServerArg(t *testing.T) {
	tests := []struct {
		name     string
		cluster  *v1.Cluster
		expected map[string]string
	}{
		{
			name:     "cluster without kube-apiserver-arg",
			cluster:  clusterWithoutKubeAPIServerArg(),
			expected: map[string]string{},
		},
		{
			name: "cluster without MachineGlobalConfig",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
				},
			},
			expected: map[string]string{},
		},
		{
			name:    "cluster with kube-apiserver-arg",
			cluster: clusterWithKubeAPIServerArg(),
			expected: map[string]string{
				"foo":  "bar",
				"foo2": "bar2",
			},
		},
		{
			name:    "cluster with kube-apiserver-arg-2",
			cluster: clusterWithKubeAPIServerArg2(),
			expected: map[string]string{
				"foo":  "bar",
				"foo2": "bar2",
				"foo3": "bar3=baz3",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetKubeAPIServerArg(tt.cluster); !equality.Semantic.DeepEqual(got, tt.expected) {
				t.Errorf("got: [%v], expected: [%v]", got, tt.expected)
			}
		})
	}
}

func Test_SetKubeAPIServerArg(t *testing.T) {
	tests := []struct {
		name     string
		arg      map[string]string
		cluster  *v1.Cluster
		expected *v1.Cluster
	}{
		{
			name: "cluster that already has kube-apiserver-arg",
			arg: map[string]string{
				"foo":  "bar",
				"foo2": "bar2",
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
							UpgradeStrategy: rkev1.ClusterUpgradeStrategy{},
							ChartValues:     rkev1.GenericMap{},
							MachineGlobalConfig: rkev1.GenericMap{
								Data: map[string]interface{}{
									"kube-apiserver-arg": "old-key=old-val",
								},
							},
						},
					},
				},
			},
			expected: clusterWithKubeAPIServerArg(),
		},
		{
			name: "cluster that does not have MachineGlobalConfig",
			arg: map[string]string{
				"foo":  "bar",
				"foo2": "bar2",
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
				},
			},
			expected: clusterWithKubeAPIServerArg(),
		},
		{
			name: "cluster does not have kube-apiserver-arg but other args",
			arg: map[string]string{
				"foo":  "bar",
				"foo2": "bar2",
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
							UpgradeStrategy: rkev1.ClusterUpgradeStrategy{},
							ChartValues:     rkev1.GenericMap{},
							MachineGlobalConfig: rkev1.GenericMap{
								Data: map[string]interface{}{
									"cni":                 "calico",
									"disable-kube-proxy":  false,
									"etcd-expose-metrics": false,
								},
							},
						},
					},
				},
			},
			expected: clusterWithKubeAPIServerArg(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setKubeAPIServerArg(tt.arg, tt.cluster)
			got := toMap(tt.cluster.Spec.RKEConfig.MachineGlobalConfig.Data["kube-apiserver-arg"])
			expected := toMap(tt.expected.Spec.RKEConfig.MachineGlobalConfig.Data["kube-apiserver-arg"])
			if !equality.Semantic.DeepEqual(got, expected) {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		})
	}
}

func Test_AddMachineSelectorFile(t *testing.T) {
	tests := []struct {
		name     string
		file     rkev1.RKEProvisioningFiles
		cluster  *v1.Cluster
		expected *v1.Cluster
	}{
		{
			name:     "cluster that does not have MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithoutMachineSelectorFile(),
			expected: clusterWithMachineSelectorFile1(),
		},
		{
			name:     "cluster that has the same MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithMachineSelectorFile1(),
			expected: clusterWithMachineSelectorFile1(),
		},
		{
			name:     "cluster that has different MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithMachineSelectorFile2(),
			expected: clusterWithMachineSelectorFile1And2(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addMachineSelectorFile(tt.file, tt.cluster)
			got := tt.cluster.Spec.RKEConfig.MachineSelectorFiles
			expected := tt.expected.Spec.RKEConfig.MachineSelectorFiles
			if !equality.Semantic.DeepEqual(got, expected) {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		})
	}
}

func Test_DropMachineSelectorFile(t *testing.T) {
	tests := []struct {
		name     string
		file     rkev1.RKEProvisioningFiles
		cluster  *v1.Cluster
		expected *v1.Cluster
	}{
		{
			name:     "cluster that does not have MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithoutMachineSelectorFile(),
			expected: clusterWithoutMachineSelectorFile(),
		},
		{
			name:     "cluster that has the same MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithMachineSelectorFile1(),
			expected: clusterWithoutMachineSelectorFile(),
		},
		{
			name:     "cluster that has different MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithMachineSelectorFile2(),
			expected: clusterWithMachineSelectorFile2(),
		},
		{
			name:     "cluster that has multiple MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithMachineSelectorFile1And2(),
			expected: clusterWithMachineSelectorFile2(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dropMachineSelectorFile(tt.file, tt.cluster)
			got := tt.cluster.Spec.RKEConfig.MachineSelectorFiles
			expected := tt.expected.Spec.RKEConfig.MachineSelectorFiles
			if !equality.Semantic.DeepEqual(got, expected) {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		})
	}
}

func Test_MachineSelectorFileExists(t *testing.T) {
	tests := []struct {
		name     string
		file     rkev1.RKEProvisioningFiles
		cluster  *v1.Cluster
		expected bool
	}{
		{
			name:     "cluster that does not have MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithoutMachineSelectorFile(),
			expected: false,
		},
		{
			name:     "cluster that has the same MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithMachineSelectorFile1(),
			expected: true,
		},
		{
			name:     "cluster that has different MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithMachineSelectorFile2(),
			expected: false,
		},
		{
			name:     "cluster that has multiple MachineSelectorFiles",
			file:     machineSelectorFile1(),
			cluster:  clusterWithMachineSelectorFile1And2(),
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MachineSelectorFileExists(tt.file, tt.cluster)
			if !equality.Semantic.DeepEqual(result, tt.expected) {
				t.Errorf("got: %v, expected: %v", result, tt.expected)
			}
		})
	}
}

func Test_GetRuntime(t *testing.T) {
	tests := []struct {
		name       string
		k8sVersion string
		expected   string
	}{
		{
			name:       "rke",
			k8sVersion: "v1.24.5-rancher1-1",
			expected:   runtimeRKE,
		},
		{
			name:       "rke2",
			k8sVersion: "v1.25.5-rke2r2",
			expected:   runtimeRKE2,
		},
		{
			name:       "k3s",
			k8sVersion: "v1.25.5+k3s1",
			expected:   runtimeK3S,
		},
		{
			name:       "invalid",
			k8sVersion: "v1.24.5-k9s",
			expected:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRuntime(tt.k8sVersion)
			if !equality.Semantic.DeepEqual(result, tt.expected) {
				t.Errorf("got: %v, expected: %v", result, tt.expected)
			}
		})
	}
}

func clusterWithoutKubeAPIServerArg() *v1.Cluster {
	return &v1.Cluster{
		Spec: v1.ClusterSpec{
			RKEConfig: &v1.RKEConfig{
				RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
					UpgradeStrategy: rkev1.ClusterUpgradeStrategy{},
					ChartValues:     rkev1.GenericMap{},
					MachineGlobalConfig: rkev1.GenericMap{
						Data: map[string]interface{}{
							"cni":                 "calico",
							"disable-kube-proxy":  false,
							"etcd-expose-metrics": false,
						}},
				},
			},
		},
	}
}

func clusterWithKubeAPIServerArg() *v1.Cluster {
	cluster := clusterWithoutKubeAPIServerArg()
	var arg []interface{}
	arg = append(arg, "foo=bar")
	arg = append(arg, "foo2=bar2")
	cluster.Spec.RKEConfig.MachineGlobalConfig.Data["kube-apiserver-arg"] = arg
	return cluster
}

func clusterWithKubeAPIServerArg2() *v1.Cluster {
	cluster := clusterWithoutKubeAPIServerArg()
	var arg []interface{}
	arg = append(arg, "foo=bar")
	arg = append(arg, "foo2=bar2")
	arg = append(arg, "foo3=bar3=baz3")
	cluster.Spec.RKEConfig.MachineGlobalConfig.Data["kube-apiserver-arg"] = arg
	return cluster
}

func machineSelectorFile2() rkev1.RKEProvisioningFiles {
	return rkev1.RKEProvisioningFiles{
		MachineLabelSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				controlPlaneRoleLabel: "true",
			},
		},
		FileSources: []rkev1.ProvisioningFileSource{
			{
				Secret: rkev1.K8sObjectFileSource{
					Name: "rke2-admission-configuration-psact",
					Items: []rkev1.KeyToPath{
						{
							Key:         "key2",
							Path:        "/etc/k3s/path2",
							Permissions: "",
						},
					},
					DefaultPermissions: "",
				},
			},
		},
	}
}

func machineSelectorFile1() rkev1.RKEProvisioningFiles {
	return rkev1.RKEProvisioningFiles{
		MachineLabelSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				controlPlaneRoleLabel: "true",
			},
		},
		FileSources: []rkev1.ProvisioningFileSource{
			{
				Secret: rkev1.K8sObjectFileSource{
					Name: "rke2-admission-configuration-psact",
					Items: []rkev1.KeyToPath{
						{
							Key:         "key1",
							Path:        "/etc/rke2/path1",
							Permissions: "",
						},
					},
					DefaultPermissions: "",
				},
			},
		},
	}
}

func clusterWithMachineSelectorFile1() *v1.Cluster {
	return &v1.Cluster{
		Spec: v1.ClusterSpec{
			RKEConfig: &v1.RKEConfig{
				RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
					MachineSelectorFiles: []rkev1.RKEProvisioningFiles{
						machineSelectorFile1(),
					},
				},
			},
		},
	}
}

func clusterWithMachineSelectorFile1And2() *v1.Cluster {
	return &v1.Cluster{
		Spec: v1.ClusterSpec{
			RKEConfig: &v1.RKEConfig{
				RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
					MachineSelectorFiles: []rkev1.RKEProvisioningFiles{
						machineSelectorFile2(),
						machineSelectorFile1(),
					},
				},
			},
		},
	}
}
func clusterWithMachineSelectorFile2() *v1.Cluster {
	return &v1.Cluster{
		Spec: v1.ClusterSpec{
			RKEConfig: &v1.RKEConfig{
				RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
					MachineSelectorFiles: []rkev1.RKEProvisioningFiles{
						machineSelectorFile2(),
					},
				},
			},
		},
	}
}

func clusterWithoutMachineSelectorFile() *v1.Cluster {
	return &v1.Cluster{
		Spec: v1.ClusterSpec{
			RKEConfig: &v1.RKEConfig{
				RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{},
			},
		},
	}
}
