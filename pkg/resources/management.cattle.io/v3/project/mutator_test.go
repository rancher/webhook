package project

import (
	"encoding/json"
	"fmt"
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	expectedIndexerName = "webhook.cattle.io/creator-role-template-index"
	expectedIndexKey    = "creatorDefaultUnlocked"
)

var (
	defaultProject = v3.Project{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testproject",
		},
		Spec: v3.ProjectSpec{
			ClusterName: "testcluster",
		},
	}
	emptyProject = func() *v3.Project {
		return &v3.Project{}
	}
)

func TestAdmit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                    string
		operation               admissionv1.Operation
		dryRun                  bool
		projectNamespaceSetting string
		oldProject              func() *v3.Project
		newProject              func() *v3.Project
		indexer                 func() ([]*v3.RoleTemplate, error)
		wantProject             func() *v3.Project
		wantErr                 bool
	}{
		{
			name:                    "dry run returns allowed",
			operation:               admissionv1.Update,
			dryRun:                  true,
			newProject:              emptyProject,
			projectNamespaceSetting: "true",
		},
		{
			name:                    "failure to decode project returns error",
			newProject:              nil,
			wantErr:                 true,
			projectNamespaceSetting: "true",
		},
		{
			name:                    "delete operation is invalid",
			operation:               admissionv1.Delete,
			newProject:              emptyProject,
			oldProject:              emptyProject,
			wantErr:                 true,
			projectNamespaceSetting: "true",
		},
		{
			name:      "update operation is valid and adds backingNamespace",
			operation: admissionv1.Update,
			newProject: func() *v3.Project {
				return &v3.Project{
					ObjectMeta: metav1.ObjectMeta{
						Name: "p-abc123",
					},
				}
			},
			oldProject: func() *v3.Project {
				return &v3.Project{
					ObjectMeta: metav1.ObjectMeta{
						Name: "p-abc123",
					},
				}
			},
			wantProject: func() *v3.Project {
				return &v3.Project{
					ObjectMeta: metav1.ObjectMeta{
						Name: "p-abc123",
					},
					Status: v3.ProjectStatus{
						BackingNamespace: "p-abc123",
					},
				}
			},
			projectNamespaceSetting: "true",
		},
		{
			name:      "update operation is valid and adds backingNamespace, even when setting is false",
			operation: admissionv1.Update,
			newProject: func() *v3.Project {
				return &v3.Project{
					ObjectMeta: metav1.ObjectMeta{
						Name: "p-abc123",
					},
				}
			},
			oldProject: func() *v3.Project {
				return &v3.Project{
					ObjectMeta: metav1.ObjectMeta{
						Name: "p-abc123",
					},
				}
			},
			wantProject: func() *v3.Project {
				return &v3.Project{
					ObjectMeta: metav1.ObjectMeta{
						Name: "p-abc123",
					},
					Status: v3.ProjectStatus{
						BackingNamespace: "p-abc123",
					},
				}
			},
			projectNamespaceSetting: "false",
		},
		{
			name:                    "connect operation is invalid",
			operation:               admissionv1.Connect,
			newProject:              emptyProject,
			oldProject:              emptyProject,
			wantErr:                 true,
			projectNamespaceSetting: "true",
		},
		{
			name:                    "indexer error",
			operation:               admissionv1.Create,
			newProject:              emptyProject,
			indexer:                 func() ([]*v3.RoleTemplate, error) { return nil, fmt.Errorf("indexer error") },
			wantErr:                 true,
			projectNamespaceSetting: "true",
		},
		{
			name:      "indexer returns empty",
			operation: admissionv1.Create,
			newProject: func() *v3.Project {
				return defaultProject.DeepCopy()
			},
			indexer: func() ([]*v3.RoleTemplate, error) { return nil, nil },
			wantProject: func() *v3.Project {
				p := defaultProject.DeepCopy()
				p.Annotations = map[string]string{
					"authz.management.cattle.io/creator-role-bindings": "{}",
				}
				p.Status.BackingNamespace = "testcluster-testproject"
				return p
			},
			projectNamespaceSetting: "true",
		},
		{
			name:      "created project gets annotation added and backing namespace",
			operation: admissionv1.Create,
			newProject: func() *v3.Project {
				return defaultProject.DeepCopy()
			},
			wantProject: func() *v3.Project {
				p := defaultProject.DeepCopy()
				p.Annotations = map[string]string{
					"authz.management.cattle.io/creator-role-bindings": "{\"required\":[\"project-owner\"]}",
				}
				p.Status.BackingNamespace = "testcluster-testproject"
				return p
			},
			projectNamespaceSetting: "true",
		},
		{
			name:      "created project adds annotation but not backing namespace if setting is false",
			operation: admissionv1.Create,
			newProject: func() *v3.Project {
				return defaultProject.DeepCopy()
			},
			wantProject: func() *v3.Project {
				p := defaultProject.DeepCopy()
				p.Annotations = map[string]string{
					"authz.management.cattle.io/creator-role-bindings": "{\"required\":[\"project-owner\"]}",
				}
				return p
			},
			projectNamespaceSetting: "false",
		},
		{
			name:      "override user-set annotations",
			operation: admissionv1.Create,
			newProject: func() *v3.Project {
				p := defaultProject.DeepCopy()
				p.Annotations = map[string]string{
					"authz.management.cattle.io/creator-role-bindings": "my own setting",
				}
				return p
			},
			wantProject: func() *v3.Project {
				p := defaultProject.DeepCopy()
				p.Annotations = map[string]string{
					"authz.management.cattle.io/creator-role-bindings": "{\"required\":[\"project-owner\"]}",
				}
				p.Status.BackingNamespace = "testcluster-testproject"
				return p
			},
			projectNamespaceSetting: "true",
		},
	}

	roleTemplates := []*v3.RoleTemplate{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "project-owner",
			},
			Context:               "project",
			DisplayName:           "Project Owner",
			ProjectCreatorDefault: true,
		},
	}
	defaultIndexer := func() ([]*v3.RoleTemplate, error) {
		return roleTemplates, nil
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			nsMock := fake.NewMockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList](ctrl)
			nsMock.EXPECT().Get(gomock.Any(), metav1.GetOptions{}).Return(nil, apierrors.NewNotFound(schema.GroupResource{}, "")).AnyTimes()
			projectMock := fake.NewMockClientInterface[*v3.Project, *v3.ProjectList](ctrl)
			projectMock.EXPECT().Get(gomock.Any(), gomock.Any(), metav1.GetOptions{}).Return(nil, apierrors.NewNotFound(schema.GroupResource{}, "")).AnyTimes()
			settingMock := fake.NewMockNonNamespacedClientInterface[*v3.Setting, *v3.SettingList](ctrl)
			settingMock.EXPECT().Get(gomock.Any(), gomock.Any()).Return(&v3.Setting{Default: test.projectNamespaceSetting}, nil).AnyTimes()
			roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](gomock.NewController(t))
			roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any())
			indexer := defaultIndexer
			if test.indexer != nil {
				indexer = test.indexer
			}
			returnedRTs, returnedErr := indexer()
			roleTemplateCache.EXPECT().GetByIndex(expectedIndexerName, expectedIndexKey).Return(returnedRTs, returnedErr).AnyTimes()

			var oldProject, newProject *v3.Project
			if test.oldProject != nil {
				oldProject = test.oldProject()
			}
			if test.newProject != nil {
				newProject = test.newProject()
			}
			req, err := createProjectRequest(oldProject, newProject, test.operation, test.dryRun)
			assert.NoError(t, err)
			m := NewMutator(nsMock, roleTemplateCache, projectMock, settingMock)

			resp, err := m.Admit(req)

			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err, "Admit failed")
			assert.Equal(t, true, resp.Allowed)
			if test.wantProject != nil {
				patchObj, err := jsonpatch.DecodePatch(resp.Patch)
				assert.NoError(t, err, "failed to decode patch from response")

				patchedJS, err := patchObj.Apply(req.Object.Raw)
				assert.NoError(t, err, "failed to apply patch to Object")

				gotObj := &v3.Project{}
				err = json.Unmarshal(patchedJS, gotObj)
				assert.NoError(t, err, "failed to unmarshal patched Object")

				assert.Equal(t, test.wantProject(), gotObj)
			} else {
				assert.Nil(t, resp.Patch, "unexpected patch request received")
			}
		})
	}
}
