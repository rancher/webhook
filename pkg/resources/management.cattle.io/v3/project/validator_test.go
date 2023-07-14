package project

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestProjectValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		operation   v1.Operation
		newProject  *v3.Project
		oldProject  *v3.Project
		namespaces  []*corev1.Namespace
		wantAllowed bool
		wantErr     bool
	}{
		{
			name:        "failure to decode project returns error",
			newProject:  nil,
			oldProject:  nil,
			wantAllowed: false,
			wantErr:     true,
		},
		{
			name:      "create new with no quotas",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test1",
					ClusterName: "testcluster",
				},
			},
			wantAllowed: true,
		},
		{
			name:      "create new with valid quotas",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			wantAllowed: true,
		},
		{
			name:      "create new with project quota present but namespace quota missing",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "create new with namespace quota present but project quota missing",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "create new with namespace quota having unexpected resource fields",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "create new with project quota having unexpected resource fields",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "create new with project quota and namespace quota having mismatched resource fields",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps:   "10",
							LimitsMemory: "2048Mi",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "create new with namespace quota greater than project quota",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "create new with negative namespace quota",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "-100",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with no quotas (noop)",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			wantAllowed: true,
		},
		{
			name:      "update to reset quotas",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota:                 nil,
					NamespaceDefaultResourceQuota: nil,
				},
			},
			wantAllowed: true,
		},
		{
			name:      "update with new valid quotas",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			wantAllowed: true,
		},
		{
			name:      "update with project quota present but namespace quota missing",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with namespace quota present but project quota missing",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			newProject: &v3.Project{
				Spec: v3.ProjectSpec{
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with namespace quota having unexpected resource fields",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			newProject: &v3.Project{
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with project quota having unexpected resource fields",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			newProject: &v3.Project{
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with project quota and namespace quota having mismatched resource fields",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			newProject: &v3.Project{
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps:   "10",
							LimitsMemory: "2048Mi",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with namespace quota greater than project quota",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			newProject: &v3.Project{
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with project quota less than used quota",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "50",
						},
					},
				},
			},
			newProject: &v3.Project{
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "60",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "50",
						},
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with project quota less than namespace quota times number of namespaces",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "20",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "5",
						},
					},
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "20",
							LimitsCPU:  "15m",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "5",
							LimitsCPU:  "10m",
						},
					},
				},
			},
			namespaces: []*corev1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testns1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testns2",
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with fields changed in project quota less than used quota",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							LimitsCPU: "100m",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							LimitsCPU: "100m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							LimitsCPU: "50m",
						},
					},
				},
			},
			newProject: &v3.Project{
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							LimitsCPU: "100m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "50",
						},
					},
				},
			},
			namespaces: []*corev1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testns1",
					},
				},
			},
			wantAllowed: true,
		},
		{
			name:      "delete regular project",
			operation: admissionv1.Delete,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			wantAllowed: true,
		},
		{
			name:      "delete system project",
			operation: admissionv1.Delete,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Labels: map[string]string{
						"authz.management.cattle.io/system-project": "true",
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with negative namespace quota",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "-200",
						},
					},
				},
			},
			wantAllowed: false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			req, err := createProjectRequest(test.oldProject, test.newProject, test.operation, false)
			assert.NoError(t, err)
			namespaceCache := fake.NewMockNonNamespacedCacheInterface[*corev1.Namespace](gomock.NewController(t))
			if test.namespaces != nil {
				namespaceCache.EXPECT().List(labels.Set(map[string]string{"field.cattle.io/projectId": test.oldProject.Name}).AsSelector()).Return(
					test.namespaces,
					nil,
				).AnyTimes()
			}
			validator := NewValidator(namespaceCache)
			admitters := validator.Admitters()
			assert.Len(t, admitters, 1)
			response, err := admitters[0].Admit(req)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.wantAllowed, response.Allowed)
		})
	}
}

func createProjectRequest(oldProject, newProject *v3.Project, operation v1.Operation, dryRun bool) (*admission.Request, error) {
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Project"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "projects"}
	req := &admission.Request{
		Context: context.Background(),
	}
	if oldProject == nil && newProject == nil {
		return req, nil
	}
	req.AdmissionRequest = v1.AdmissionRequest{
		Kind:            gvk,
		Resource:        gvr,
		RequestKind:     &gvk,
		RequestResource: &gvr,
		Operation:       operation,
		Object:          runtime.RawExtension{},
		OldObject:       runtime.RawExtension{},
		DryRun:          &dryRun,
	}
	if newProject != nil {
		var err error
		req.Object.Raw, err = json.Marshal(newProject)
		if err != nil {
			return nil, err
		}
	}
	if oldProject != nil {
		obj, err := json.Marshal(oldProject)
		if err != nil {
			return nil, err
		}
		req.OldObject = runtime.RawExtension{
			Raw: obj,
		}
	}
	return req, nil
}
