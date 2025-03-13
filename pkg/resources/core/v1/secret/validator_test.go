package secret

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAdmit(t *testing.T) {
	const secretName = "test-secret"
	const secretNamespace = "test-ns"
	tests := []struct {
		name                       string
		hasRoleRefs                bool
		hasRoleBindingRefs         bool
		hasOrphanDelete            bool
		hasOrphanPropagationDelete bool
		secretDecodeError          bool
		optionsDecodeError         bool
		roleIndexerError           error
		roleBindingIndexerError    error

		wantAdmit bool
		wantError bool
	}{
		{
			name:      "no refs, can delete",
			wantAdmit: true,
		},
		{
			name:            "no refs, can orphan",
			hasOrphanDelete: true,
			wantAdmit:       true,
		},
		{
			name:                       "no refs, can orphan through propagation",
			hasOrphanPropagationDelete: true,
			wantAdmit:                  true,
		},
		{
			name:        "role refs, can delete",
			hasRoleRefs: true,
			wantAdmit:   true,
		},
		{
			name:            "role refs, cannot orphan",
			hasRoleRefs:     true,
			hasOrphanDelete: true,
			wantAdmit:       false,
		},
		{
			name:                       "role refs, cannot orphan through propagation",
			hasRoleRefs:                true,
			hasOrphanPropagationDelete: true,
			wantAdmit:                  false,
		},
		{
			name:               "role binding refs, can delete",
			hasRoleBindingRefs: true,
			wantAdmit:          true,
		},
		{
			name:               "role binding refs, cannot orphan",
			hasRoleBindingRefs: true,
			hasOrphanDelete:    true,
			wantAdmit:          false,
		},
		{
			name:                       "role binding refs, cannot orphan through propagation",
			hasRoleBindingRefs:         true,
			hasOrphanPropagationDelete: true,
			wantAdmit:                  false,
		},
		{
			name:               "role and role binding refs, can delete",
			hasRoleRefs:        true,
			hasRoleBindingRefs: true,
			wantAdmit:          true,
		},
		{
			name:               "role and role binding refs, cannot orphan",
			hasRoleRefs:        true,
			hasRoleBindingRefs: true,
			hasOrphanDelete:    true,
			wantAdmit:          false,
		},
		{
			name:                       "role and role binding refs, cannot orphan through propagation",
			hasRoleRefs:                true,
			hasRoleBindingRefs:         true,
			hasOrphanPropagationDelete: true,
			wantAdmit:                  false,
		},
		{
			name:                       "secret decode error",
			hasRoleRefs:                true,
			secretDecodeError:          true,
			hasOrphanPropagationDelete: true,
			wantError:                  true,
		},
		{
			name:                       "deleteOpts decode error",
			hasRoleRefs:                true,
			optionsDecodeError:         true,
			hasOrphanPropagationDelete: true,
			wantError:                  true,
		},
		{
			name:                       "role indexer error",
			hasRoleBindingRefs:         true,
			roleIndexerError:           fmt.Errorf("indexer error"),
			hasOrphanPropagationDelete: true,
			wantError:                  true,
		},
		{
			name:                       "role binding indexer error",
			hasRoleRefs:                true,
			roleBindingIndexerError:    fmt.Errorf("indexer error"),
			hasOrphanPropagationDelete: true,
			wantError:                  true,
		},
		{
			name:                       "role and role binding indexer error",
			roleIndexerError:           fmt.Errorf("indexer error"),
			roleBindingIndexerError:    fmt.Errorf("indexer error"),
			hasOrphanPropagationDelete: true,
			wantError:                  true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			var roles []*rbacv1.Role
			var roleBindings []*rbacv1.RoleBinding
			secretOwnerRef := metav1.OwnerReference{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       secretName,
				UID:        "1",
			}
			if test.hasRoleRefs {
				roles = []*rbacv1.Role{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:            "test-role",
							Namespace:       secretNamespace,
							OwnerReferences: []metav1.OwnerReference{secretOwnerRef},
						},
					},
				}
			}
			if test.hasRoleBindingRefs {
				roleBindings = []*rbacv1.RoleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:            "test-role-binding",
							Namespace:       secretNamespace,
							OwnerReferences: []metav1.OwnerReference{secretOwnerRef},
						},
					},
				}
			}

			secret := corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: secretNamespace,
				},
			}

			secretGVR := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
			secretGVK := metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:             "2",
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					Name:            secretName,
					Namespace:       secretNamespace,
					Operation:       admissionv1.Delete,
					UserInfo:        v1authentication.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			invalidObj := struct {
				Immutable          string
				GracePeriodSeconds string
			}{Immutable: "some-value", GracePeriodSeconds: "some-value"}

			var err error
			req.OldObject.Raw, err = json.Marshal(secret)
			assert.NoError(t, err)

			if test.secretDecodeError {
				notASecret := invalidObj
				req.OldObject.Raw, err = json.Marshal(notASecret)
				assert.NoError(t, err)
			}

			deleteOpts := metav1.DeleteOptions{}
			if test.hasOrphanPropagationDelete {
				orphanPolicy := metav1.DeletePropagationOrphan
				deleteOpts.PropagationPolicy = &orphanPolicy
			}
			if test.hasOrphanDelete {
				orphan := true
				deleteOpts.OrphanDependents = &orphan
			}

			req.Options.Raw, err = json.Marshal(deleteOpts)
			assert.NoError(t, err)

			if test.optionsDecodeError {
				notDeleteOptions := invalidObj
				req.Options.Raw, err = json.Marshal(notDeleteOptions)
				assert.NoError(t, err)
			}

			roleCache := fake.NewMockCacheInterface[*rbacv1.Role](ctrl)
			roleBindingCache := fake.NewMockCacheInterface[*rbacv1.RoleBinding](ctrl)

			roleCache.EXPECT().GetByIndex(roleOwnerIndex, fmt.Sprintf("%s/%s", secretNamespace, secretName)).Return(roles, test.roleIndexerError).AnyTimes()
			roleBindingCache.EXPECT().GetByIndex(roleBindingOwnerIndex, fmt.Sprintf("%s/%s", secretNamespace, secretName)).Return(roleBindings, test.roleBindingIndexerError).AnyTimes()

			roleCache.EXPECT().AddIndexer(roleOwnerIndex, gomock.Any())
			roleBindingCache.EXPECT().AddIndexer(roleBindingOwnerIndex, gomock.Any())
			validator := NewValidator(roleCache, roleBindingCache)

			admitters := validator.Admitters()
			assert.Len(t, admitters, 1)
			response, err := admitters[0].Admit(&req)
			if test.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.wantAdmit, response.Allowed)
			}
		})
	}
}

func Test_secretOwnerIndexer(t *testing.T) {
	secretName := "test-secret"
	secretNamespace := "test-ns"
	tests := []struct {
		name        string
		ownerRefs   []metav1.OwnerReference
		wantStrings []string
	}{
		{
			name: "secret owner index",
			ownerRefs: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Secret",
					Name:       secretName,
					UID:        "1",
				},
			},
			wantStrings: []string{fmt.Sprintf("%s/%s", secretNamespace, secretName)},
		},
		{
			name: "different kind owner",
			ownerRefs: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Deployment",
					Name:       secretName,
					UID:        "1",
				},
			},
			wantStrings: nil,
		},
		{
			name: "different group owner",
			ownerRefs: []metav1.OwnerReference{
				{
					APIVersion: "v3",
					Kind:       "Secret",
					Name:       secretName,
					UID:        "1",
				},
			},
			wantStrings: nil,
		},
		{
			name: "one secret owner, one other owner",
			ownerRefs: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Secret",
					Name:       secretName,
					UID:        "1",
				},
				{
					APIVersion: "v3",
					Kind:       "Deployment",
					Name:       "test-dep",
					UID:        "1",
				},
			},
			wantStrings: []string{fmt.Sprintf("%s/%s", secretNamespace, secretName)},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			meta := metav1.ObjectMeta{OwnerReferences: test.ownerRefs, Namespace: secretNamespace}
			assert.Equal(t, test.wantStrings, secretOwnerIndexer(meta))
		})
	}
}
