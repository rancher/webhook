package cluster

import (
	"encoding/json"
	"reflect"
	"testing"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	data2 "github.com/rancher/wrangler/v3/pkg/data"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
			if got := getKubeAPIServerArg(tt.cluster); !equality.Semantic.DeepEqual(got, tt.expected) {
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
			file:     machineSelectorFile2(),
			cluster:  clusterWithMachineSelectorFile1(),
			expected: clusterWithMachineSelectorFile1And2(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addMachineSelectorFile(&tt.file, tt.cluster)
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
		name             string
		fileToDrop       rkev1.RKEProvisioningFiles
		cluster          *v1.Cluster
		expected         *v1.Cluster
		ignoreValueCheck bool
	}{
		{
			name:             "cluster that does not have MachineSelectorFiles",
			fileToDrop:       machineSelectorFile1(),
			cluster:          clusterWithoutMachineSelectorFile(),
			expected:         clusterWithoutMachineSelectorFile(),
			ignoreValueCheck: false,
		},
		{
			name:             "cluster that has the same MachineSelectorFiles",
			fileToDrop:       machineSelectorFile1(),
			cluster:          clusterWithMachineSelectorFile1(),
			expected:         clusterWithoutMachineSelectorFile(),
			ignoreValueCheck: false,
		},
		{
			name:             "cluster that has different MachineSelectorFiles",
			fileToDrop:       machineSelectorFile1(),
			cluster:          clusterWithMachineSelectorFile2(),
			expected:         clusterWithMachineSelectorFile2(),
			ignoreValueCheck: false,
		},
		{
			name:             "cluster that has multiple MachineSelectorFiles - ignore value check",
			fileToDrop:       machineSelectorFile1(),
			cluster:          clusterWithMachineSelectorFile1And2And3(),
			expected:         clusterWithMachineSelectorFile1And2(),
			ignoreValueCheck: true,
		},
		{
			name:             "cluster that has multiple MachineSelectorFiles - enforce value check",
			fileToDrop:       machineSelectorFile1(),
			cluster:          clusterWithMachineSelectorFile1And2And3(),
			expected:         clusterWithMachineSelectorFile2And3(),
			ignoreValueCheck: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dropMachineSelectorFile(&tt.fileToDrop, tt.cluster, tt.ignoreValueCheck)
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
		name             string
		file             rkev1.RKEProvisioningFiles
		cluster          *v1.Cluster
		ignoreValueCheck bool
		expected         bool
	}{
		{
			name:             "cluster that does not have MachineSelectorFiles",
			file:             machineSelectorFile1(),
			cluster:          clusterWithoutMachineSelectorFile(),
			ignoreValueCheck: false,
			expected:         false,
		},
		{
			name:             "cluster that has the same MachineSelectorFiles",
			file:             machineSelectorFile1(),
			cluster:          clusterWithMachineSelectorFile1(),
			ignoreValueCheck: false,
			expected:         true,
		},
		{
			name:             "cluster that has different MachineSelectorFiles",
			file:             machineSelectorFile1(),
			cluster:          clusterWithMachineSelectorFile2(),
			ignoreValueCheck: false,
			expected:         false,
		},
		{
			name:             "cluster that has multiple MachineSelectorFiles - ignore value check",
			file:             machineSelectorFile3(),
			cluster:          clusterWithMachineSelectorFile1And2(),
			ignoreValueCheck: true,
			expected:         true,
		},
		{
			name:             "cluster that has multiple MachineSelectorFiles - enforce value check",
			file:             machineSelectorFile3(),
			cluster:          clusterWithMachineSelectorFile1And2(),
			ignoreValueCheck: false,
			expected:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := machineSelectorFileExists(&tt.file, tt.cluster, tt.ignoreValueCheck)
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
			result := getRuntime(tt.k8sVersion)
			if !equality.Semantic.DeepEqual(result, tt.expected) {
				t.Errorf("got: %v, expected: %v", result, tt.expected)
			}
		})
	}
}

func Test_cleanupExpectedValue(t *testing.T) {
	tests := []struct {
		name      string
		inputFile rkev1.RKEProvisioningFiles
		expected  rkev1.RKEProvisioningFiles
	}{
		{
			name: "file with values for the ExpectedValue field",
			inputFile: rkev1.RKEProvisioningFiles{
				MachineLabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						controlPlaneRoleLabel: "true",
					},
				},
				FileSources: []rkev1.ProvisioningFileSource{
					{
						Secret: rkev1.K8sObjectFileSource{
							Name: "foo",
							Items: []rkev1.KeyToPath{
								{
									Key:  "key1",
									Path: "/etc/rke2/path1",
									Hash: "expected-value-for-file1",
								},
							},
						},
						ConfigMap: rkev1.K8sObjectFileSource{
							Name: "bar",
							Items: []rkev1.KeyToPath{
								{
									Key:  "key2",
									Path: "/etc/rke2/path2",
									Hash: "expected-value2",
								},
							},
						},
					},
				},
			},
			expected: rkev1.RKEProvisioningFiles{
				MachineLabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						controlPlaneRoleLabel: "true",
					},
				},
				FileSources: []rkev1.ProvisioningFileSource{
					{
						Secret: rkev1.K8sObjectFileSource{
							Name: "foo",
							Items: []rkev1.KeyToPath{
								{
									Key:  "key1",
									Path: "/etc/rke2/path1",
								},
							},
						},
						ConfigMap: rkev1.K8sObjectFileSource{
							Name: "bar",
							Items: []rkev1.KeyToPath{
								{
									Key:  "key2",
									Path: "/etc/rke2/path2",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHash(&tt.inputFile)
			if !equality.Semantic.DeepEqual(tt.inputFile, tt.expected) {
				t.Errorf("got: %v, expected: %v", tt.inputFile, tt.expected)
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

func machineSelectorFile3() rkev1.RKEProvisioningFiles {
	file := machineSelectorFile1()
	file.FileSources[0].Secret.Items[0].Hash = "expected-value-for-file-3"
	return file
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
							Hash:        "expected-value-for-file1",
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

func clusterWithMachineSelectorFile1And2And3() *v1.Cluster {
	return &v1.Cluster{
		Spec: v1.ClusterSpec{
			RKEConfig: &v1.RKEConfig{
				RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
					MachineSelectorFiles: []rkev1.RKEProvisioningFiles{
						machineSelectorFile1(),
						machineSelectorFile2(),
						machineSelectorFile3(),
					},
				},
			},
		},
	}
}

func clusterWithMachineSelectorFile2And3() *v1.Cluster {
	return &v1.Cluster{
		Spec: v1.ClusterSpec{
			RKEConfig: &v1.RKEConfig{
				RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
					MachineSelectorFiles: []rkev1.RKEProvisioningFiles{
						machineSelectorFile2(),
						machineSelectorFile3(),
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
						machineSelectorFile1(),
						machineSelectorFile2(),
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

func TestAdmitPreserveUnknownFields(t *testing.T) {
	cluster := &v1.Cluster{}
	data, err := data2.Convert(cluster)
	assert.Nil(t, err)

	data.SetNested("test", "spec", "unknownField")
	raw, err := json.Marshal(data)
	assert.Nil(t, err)

	request := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Object: runtime.RawExtension{
				Raw: raw,
			},
			OldObject: runtime.RawExtension{
				Raw: raw,
			},
		},
	}

	m := ProvisioningClusterMutator{}

	request.Operation = admissionv1.Create
	response, err := m.Admit(request)
	assert.Nil(t, err)
	assert.Equal(t, response.Patch, []byte(`[{"op":"add","path":"/metadata/annotations","value":{"field.cattle.io/creatorId":""}}]`))

	request.Operation = admissionv1.Update
	response, err = m.Admit(request)
	assert.Nil(t, err)
	assert.Nil(t, response.Patch)

}

func TestDynamicSchemaDrop(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		request    *admission.Request
		cluster    *v1.Cluster
		oldCluster *v1.Cluster
		expected   []v1.RKEMachinePool
	}{
		{
			name:    "not v2prov cluster",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{},
		},
		{
			name:    "no schema present on old or new cluster",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name: "a",
							},
						},
					},
				},
			},
			expected: []v1.RKEMachinePool{
				{
					Name: "a",
				},
			},
		},
		{
			name:    "matching schema present on old and new cluster",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name:              "a",
								DynamicSchemaSpec: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name:              "a",
								DynamicSchemaSpec: "a",
							},
						},
					},
				},
			},
			expected: []v1.RKEMachinePool{
				{
					Name:              "a",
					DynamicSchemaSpec: "a",
				},
			},
		},
		{
			name:    "schema present on old cluster but not new cluster without annotation",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name:              "a",
								DynamicSchemaSpec: "a",
							},
						},
					},
				},
			},
			expected: []v1.RKEMachinePool{
				{
					Name:              "a",
					DynamicSchemaSpec: "a",
				},
			},
		},
		{
			name:    "schema present on old cluster but not new cluster with false annotation",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"provisioning.cattle.io/allow-dynamic-schema-drop": "false"}},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name:              "a",
								DynamicSchemaSpec: "a",
							},
						},
					},
				},
			},
			expected: []v1.RKEMachinePool{
				{
					Name:              "a",
					DynamicSchemaSpec: "a",
				},
			},
		},
		{
			name:    "schema present on old cluster and new cluster with true annotation",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"provisioning.cattle.io/allow-dynamic-schema-drop": "true"}},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name:              "a",
								DynamicSchemaSpec: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name:              "a",
								DynamicSchemaSpec: "a",
							},
						},
					},
				},
			},
			expected: []v1.RKEMachinePool{
				{
					Name:              "a",
					DynamicSchemaSpec: "a",
				},
			},
		},
		{
			name:    "schema present on old cluster but not new cluster with true annotation",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"provisioning.cattle.io/allow-dynamic-schema-drop": "true"}},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name:              "a",
								DynamicSchemaSpec: "a",
							},
						},
					},
				},
			},
			expected: []v1.RKEMachinePool{
				{
					Name: "a",
				},
			},
		},
		{
			name:    "new machine pool without schema",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name:              "a",
								DynamicSchemaSpec: "a",
							},
							{
								Name: "b",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						MachinePools: []v1.RKEMachinePool{
							{
								Name:              "a",
								DynamicSchemaSpec: "a",
							},
						},
					},
				},
			},
			expected: []v1.RKEMachinePool{
				{
					Name:              "a",
					DynamicSchemaSpec: "a",
				},
				{
					Name: "b",
				},
			},
		},
	}

	m := ProvisioningClusterMutator{}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			resp := m.handleDynamicSchemaDrop(tt.request, tt.oldCluster, tt.cluster)
			assert.True(t, resp.Allowed)
			if tt.expected != nil {
				assert.True(t, reflect.DeepEqual(tt.expected, tt.cluster.Spec.RKEConfig.MachinePools))
			}
		})
	}
}
