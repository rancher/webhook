package project

import (
	"encoding/json"
	"fmt"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	expectedIndexerName = "webhook.cattle.io/creator-role-template-index"
	expectedIndexKey    = "creatorDefaultUnlocked"
)

func TestAdmit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		operation  admissionv1.Operation
		dryRun     bool
		oldProject *v3.Project
		newProject *v3.Project
		indexer    func() ([]*v3.RoleTemplate, error)
		wantPatch  []map[string]interface{}
		wantErr    bool
	}{
		{
			name:       "dry run returns allowed",
			operation:  admissionv1.Update,
			dryRun:     true,
			newProject: &v3.Project{},
		},
		{
			name:       "failure to decode project returns error",
			newProject: nil,
			wantErr:    true,
		},
		{
			name:       "delete operation is invalid",
			operation:  admissionv1.Delete,
			newProject: &v3.Project{},
			oldProject: &v3.Project{},
			wantErr:    true,
		},
		{
			name:       "update operation is invalid",
			operation:  admissionv1.Update,
			newProject: &v3.Project{},
			oldProject: &v3.Project{},
			wantErr:    true,
		},
		{
			name:       "connect operation is invalid",
			operation:  admissionv1.Connect,
			newProject: &v3.Project{},
			oldProject: &v3.Project{},
			wantErr:    true,
		},
		{
			name:       "indexer error",
			operation:  admissionv1.Create,
			newProject: &v3.Project{},
			indexer:    func() ([]*v3.RoleTemplate, error) { return nil, fmt.Errorf("indexer error") },
			wantErr:    true,
		},
		{
			name:      "indexer returns empty",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testproject",
				},
			},
			indexer: func() ([]*v3.RoleTemplate, error) { return nil, nil },
			wantPatch: []map[string]interface{}{
				{
					"op":   "add",
					"path": "/metadata/annotations",
					"value": map[string]string{
						"authz.management.cattle.io/creator-role-bindings": "{}",
					},
				},
			},
		},
		{
			name:      "created project gets annotation added",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testproject",
				},
			},
			wantPatch: []map[string]interface{}{
				{
					"op":   "add",
					"path": "/metadata/annotations",
					"value": map[string]string{
						"authz.management.cattle.io/creator-role-bindings": "{\"required\":[\"project-owner\"]}",
					},
				},
			},
		},
		{
			name:      "override user-set annotations",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testproject",
					Annotations: map[string]string{
						"authz.management.cattle.io/creator-role-bindings": "my own setting",
					},
				},
			},
			wantPatch: []map[string]interface{}{
				{
					"op":    "replace",
					"path":  "/metadata/annotations/authz.management.cattle.io~1creator-role-bindings",
					"value": "{\"required\":[\"project-owner\"]}",
				},
			},
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
			req, err := createProjectRequest(test.oldProject, test.newProject, test.operation, test.dryRun)
			assert.NoError(t, err)
			roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](gomock.NewController(t))
			roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any())
			indexer := defaultIndexer
			if test.indexer != nil {
				indexer = test.indexer
			}
			returnedRTs, returnedErr := indexer()
			roleTemplateCache.EXPECT().GetByIndex(expectedIndexerName, expectedIndexKey).Return(returnedRTs, returnedErr).AnyTimes()
			m := NewMutator(roleTemplateCache)
			resp, err := m.Admit(req)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.Equal(t, true, resp.Allowed)
			var wantPatch []byte
			if test.wantPatch != nil {
				wantPatch, err = json.Marshal(test.wantPatch)
				assert.NoError(t, err)
			}
			assert.Equal(t, string(wantPatch), string(resp.Patch))
		})
	}
}
