package secret

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	ctrlv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	authenicationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	secretGVR = metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	secretGVK = metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
)

func Test_roleBindingIndexer(t *testing.T) {
	testNamespace := "test-ns"
	createBinding := func(roleRefKind string, ownerRefs ...metav1.OwnerReference) rbacv1.RoleBinding {
		return rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "testbinding",
				Namespace:       testNamespace,
				OwnerReferences: ownerRefs,
			},
			RoleRef: rbacv1.RoleRef{
				Kind: roleRefKind,
				Name: "test",
			},
		}
	}
	tests := []struct {
		name    string
		binding rbacv1.RoleBinding
		indexes []string
	}{
		{
			name:    "no owner refs",
			binding: createBinding("Role"),
			indexes: nil,
		},
		{
			name: "secret owner, clusterRole role ref",
			binding: createBinding("ClusterRole",
				metav1.OwnerReference{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Secret",
					Name:       "test-secret",
				}),
			indexes: nil,
		},
		{
			name: "secret owner, role role ref",
			binding: createBinding("Role",
				metav1.OwnerReference{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Secret",
					Name:       "test-secret",
				}),
			indexes: []string{fmt.Sprintf("%s/%s", testNamespace, "test-secret")},
		},
		{
			name: "non-secret owner, role ref",
			binding: createBinding("Role",
				metav1.OwnerReference{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Pods",
					Name:       "test-pod",
				}),
			indexes: nil,
		},
		{
			name: "secret owner and non-secret-owner, role role ref",
			binding: createBinding("Role",
				metav1.OwnerReference{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Secret",
					Name:       "test-secret",
				},
				metav1.OwnerReference{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Pods",
					Name:       "test-pods",
				}),
			indexes: []string{fmt.Sprintf("%s/%s", testNamespace, "test-secret")},
		},
		{
			name: "2 secret owners, role role ref",
			binding: createBinding("Role",
				metav1.OwnerReference{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Secret",
					Name:       "test-secret",
				},
				metav1.OwnerReference{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Secret",
					Name:       "test-secret-2",
				}),
			indexes: []string{fmt.Sprintf("%s/%s", testNamespace, "test-secret"), fmt.Sprintf("%s/%s", testNamespace, "test-secret-2")},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			indexes, err := roleBindingIndexer(&test.binding)
			require.NoError(t, err)
			require.Equal(t, test.indexes, indexes)
		})
	}
}

func TestMutatorAdmitOnDelete(t *testing.T) {
	const secretName = "test-secret"
	const secretNamespace = "test-ns"

	testValidRoleNorman := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testnormanrole",
			Namespace: secretNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"*"},
				ResourceNames: []string{secretName},
				Resources:     []string{"secrets"},
				Verbs:         []string{"*"},
			},
		},
	}
	testValidRoleNormanRedacted := testValidRoleNorman.DeepCopy()
	testValidRoleNormanRedacted.Rules[0].Verbs = []string{"delete"}
	testValidRole := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testrole",
			Namespace: secretNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				ResourceNames: []string{secretName},
				Resources:     []string{"secrets"},
				Verbs:         []string{"get", "update", "delete"},
			},
		},
	}
	testValidRoleRedacted := testValidRole.DeepCopy()
	testValidRoleRedacted.Rules[0].Verbs = []string{"delete"}
	testInValidRole := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testinvalidrole",
			Namespace: secretNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"notvalid"},
				ResourceNames: []string{secretName},
				Resources:     []string{"secrets"},
				Verbs:         []string{"get"},
			},
			{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
			{
				APIGroups:     []string{""},
				Resources:     []string{"nodes"},
				ResourceNames: []string{secretName},
				Verbs:         []string{"get"},
			},
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{secretName},
				Verbs:         []string{"notrealverb"},
			},
		},
	}
	testBinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testBinding",
			Namespace: secretNamespace,
		},
	}
	testSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
		},
	}

	invalidSecret := struct {
		Immutable          string
		GracePeriodSeconds string
	}{Immutable: "some-value", GracePeriodSeconds: "some-value"}

	tests := []struct {
		name              string
		operation         admissionv1.Operation
		ownedRoleBindings []*rbacv1.RoleBinding

		hasSecretDecodeError bool
		bindingIndexerError  error
		roleCacheError       error
		updateRoleError      error

		wantUpdatedRoles []*rbacv1.Role
		wantAdmit        bool
		wantErr          bool
	}{
		{
			name:      "invalid operation update",
			operation: admissionv1.Update,
			wantErr:   true,
		},
		{
			name:      "invalid operation connect",
			operation: admissionv1.Connect,
			wantErr:   true,
		},
		{
			name:              "redact norman role",
			operation:         admissionv1.Delete,
			ownedRoleBindings: []*rbacv1.RoleBinding{addRoleRefToBinding(testValidRoleNorman, testBinding)},
			wantUpdatedRoles:  []*rbacv1.Role{testValidRoleNormanRedacted},
			wantAdmit:         true,
		},
		{
			name:              "redact role",
			operation:         admissionv1.Delete,
			ownedRoleBindings: []*rbacv1.RoleBinding{addRoleRefToBinding(testValidRole, testBinding)},
			wantUpdatedRoles:  []*rbacv1.Role{testValidRoleRedacted},
			wantAdmit:         true,
		},
		{
			name:              "don't redact role",
			operation:         admissionv1.Delete,
			ownedRoleBindings: []*rbacv1.RoleBinding{addRoleRefToBinding(testInValidRole, testBinding)},
			wantUpdatedRoles:  []*rbacv1.Role{},
			wantAdmit:         true,
		},
		{
			name:                "indexer error",
			operation:           admissionv1.Delete,
			ownedRoleBindings:   []*rbacv1.RoleBinding{addRoleRefToBinding(testValidRole, testBinding)},
			bindingIndexerError: fmt.Errorf("indexer error"),
			wantErr:             true,
		},
		{
			name:                 "decode error",
			operation:            admissionv1.Delete,
			hasSecretDecodeError: true,
			wantErr:              true,
		},
		{
			name:              "cache generic error",
			operation:         admissionv1.Delete,
			ownedRoleBindings: []*rbacv1.RoleBinding{addRoleRefToBinding(testValidRole, testBinding)},
			roleCacheError:    fmt.Errorf("generic error"),
			wantErr:           true,
		},
		{
			name:              "cache not found error",
			operation:         admissionv1.Delete,
			ownedRoleBindings: []*rbacv1.RoleBinding{addRoleRefToBinding(testValidRole, testBinding)},
			roleCacheError:    apierrors.NewNotFound(schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "roles"}, testValidRole.Name),
			wantAdmit:         true,
		},
		{
			name:              "update generic error",
			operation:         admissionv1.Delete,
			ownedRoleBindings: []*rbacv1.RoleBinding{addRoleRefToBinding(testValidRole, testBinding)},
			updateRoleError:   fmt.Errorf("genericError"),
			wantUpdatedRoles:  []*rbacv1.Role{testValidRoleRedacted},
			wantErr:           true,
		},
		{
			name:              "update not found error",
			operation:         admissionv1.Delete,
			ownedRoleBindings: []*rbacv1.RoleBinding{addRoleRefToBinding(testValidRole, testBinding)},
			updateRoleError:   apierrors.NewNotFound(schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "roles"}, testValidRole.Name),
			wantUpdatedRoles:  []*rbacv1.Role{testValidRoleRedacted},
			wantAdmit:         true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:             "2",
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					Name:            secretName,
					Namespace:       secretNamespace,
					Operation:       test.operation,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			var decodeObject any
			if test.hasSecretDecodeError {
				decodeObject = invalidSecret
			} else {
				decodeObject = testSecret
			}
			var err error
			switch test.operation {
			case admissionv1.Delete:
				req.OldObject.Raw, err = json.Marshal(decodeObject)
				require.NoError(t, err)
			case admissionv1.Create:
				req.Object.Raw, err = json.Marshal(decodeObject)
				require.NoError(t, err)
			}

			ctrl := gomock.NewController(t)

			roleBindingController := fake.NewMockControllerInterface[*rbacv1.RoleBinding, *rbacv1.RoleBindingList](ctrl)
			roleBindingCache := fake.NewMockCacheInterface[*rbacv1.RoleBinding](ctrl)
			roleBindingController.EXPECT().Cache().Return(roleBindingCache).AnyTimes()

			roleBindingCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
			roleBindingCache.EXPECT().GetByIndex(gomock.Any(), fmt.Sprintf("%s/%s", secretNamespace, secretName)).Return(test.ownedRoleBindings, test.bindingIndexerError).AnyTimes()

			roleController := fake.NewMockControllerInterface[*rbacv1.Role, *rbacv1.RoleList](ctrl)
			roleCache := fake.NewMockCacheInterface[*rbacv1.Role](ctrl)
			roleController.EXPECT().Cache().Return(roleCache).AnyTimes()
			for _, role := range []rbacv1.Role{testValidRole, testValidRoleNorman, testInValidRole} {
				role := role
				roleCache.EXPECT().Get(role.Namespace, role.Name).Return(role.DeepCopy(), test.roleCacheError).AnyTimes()
			}

			for _, role := range test.wantUpdatedRoles {
				role := role
				roleController.EXPECT().Update(role).DoAndReturn(func(_ *rbacv1.Role) (*rbacv1.Role, error) {
					return role, test.updateRoleError
				}).Times(1)
			}

			mutator := NewMutator(roleController, roleBindingController, nil, nil)
			resp, err := mutator.Admit(&req)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.wantAdmit, resp.Allowed)
			}
		})
	}
}

func TestMutatorAdmitOnCreate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		secret    corev1.Secret
		wantAdmit bool
		wantErr   bool
	}{
		{
			name:      "create secret",
			secret:    corev1.Secret{},
			wantAdmit: true,
		},
		{
			name: "create cloud credential secret",
			secret: corev1.Secret{
				Type: "provisioning.cattle.io/cloud-credential",
			},
			wantAdmit: true,
		},
	}

	ctrl := gomock.NewController(t)
	roleBindingController := fake.NewMockControllerInterface[*rbacv1.RoleBinding, *rbacv1.RoleBindingList](ctrl)
	roleController := fake.NewMockControllerInterface[*rbacv1.Role, *rbacv1.RoleList](ctrl)
	roleBindingCache := fake.NewMockCacheInterface[*rbacv1.RoleBinding](ctrl)
	roleBindingController.EXPECT().Cache().Return(roleBindingCache).AnyTimes()
	roleBindingCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())

	mutator := NewMutator(roleController, roleBindingController, nil, nil)

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:             "2",
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					Name:            "my-secret",
					Namespace:       "test-ns",
					Operation:       admissionv1.Create,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			var err error
			req.Object.Raw, err = json.Marshal(test.secret)
			require.NoError(t, err)

			resp, err := mutator.Admit(&req)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.wantAdmit, resp.Allowed)
			}
		})
	}
}

func addRoleRefToBinding(role rbacv1.Role, binding rbacv1.RoleBinding) *rbacv1.RoleBinding {
	newBinding := binding.DeepCopy()
	newBinding.RoleRef = rbacv1.RoleRef{
		Kind: "Role",
		Name: role.Name,
	}
	return newBinding
}

func TestAdmitLocalUserPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	rawSecret, err := json.Marshal(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-user",
		},
		Data: map[string][]byte{
			"password": []byte("password"),
		},
	})
	assert.NoError(t, err)
	rawPbkdf2HashedSecret, err := json.Marshal(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-user",
			Annotations: map[string]string{
				passwordHashAnnotation: pbkdf2sha3512Hash,
			},
		},
		Data: map[string][]byte{
			"password": []byte("password"),
		},
	})
	assert.NoError(t, err)
	rawBcryptHashedSecret, err := json.Marshal(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-user",
			Annotations: map[string]string{
				passwordHashAnnotation: bcryptHash,
			},
		},
		Data: map[string][]byte{
			"password": []byte("password"),
		},
	})
	assert.NoError(t, err)

	fakeUser := &v3.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-user",
		},
		Username: "test",
	}
	tests := map[string]struct {
		request           *admission.Request
		hasher            passwordHasher
		mockSettingsCache func() ctrlv3.SettingCache
		mockUserCache     func() ctrlv3.UserCache
		wantAllowed       bool
		wantPatch         string
		wantErr           string
	}{
		"password is successfully hashed": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Namespace:       localUserPasswordsNamespace,
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user"},
					Object: runtime.RawExtension{
						Raw: rawSecret,
					},
				},
			},
			hasher: func(_ string) ([]byte, []byte, error) {
				return []byte("hashedPassword"), []byte("salt"), nil
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
				mock.EXPECT().Get(passwordMinLengthSetting).Return(&v3.Setting{
					Value: "5",
				}, nil)

				return mock
			},
			mockUserCache: func() ctrlv3.UserCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
				mock.EXPECT().Get("test-user").Return(fakeUser, nil)

				return mock
			},
			wantPatch:   `[{"op":"add","path":"/metadata/ownerReferences","value":[{"apiVersion":"","kind":"","name":"test-user","uid":""}]},{"op":"add","path":"/metadata/annotations","value":{"cattle.io/password-hash":"pbkdf2sha3512"}},{"op":"replace","path":"/data/password","value":"aGFzaGVkUGFzc3dvcmQ="},{"op":"add","path":"/data/salt","value":"c2FsdA=="}]`, // aGFzaGVkUGFzc3dvcmQ= -> hashedPassword base64 encoded, and c2FsdA==" => salt base64 encoded
			wantAllowed: true,
		},
		"password was already hashed using pbkdf2": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Namespace:       localUserPasswordsNamespace,
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user"},
					Object: runtime.RawExtension{
						Raw: rawPbkdf2HashedSecret,
					},
				},
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
			},
			mockUserCache: func() ctrlv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			wantAllowed: true,
		},
		"password was already hashed using bcrypt": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Namespace:       localUserPasswordsNamespace,
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user"},
					Object: runtime.RawExtension{
						Raw: rawBcryptHashedSecret,
					},
				},
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
			},
			mockUserCache: func() ctrlv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			wantAllowed: true,
		},

		"password is shorter than password-min-length setting": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Namespace:       localUserPasswordsNamespace,
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user"},
					Object: runtime.RawExtension{
						Raw: rawSecret,
					},
				},
			},
			hasher: func(_ string) ([]byte, []byte, error) {
				return []byte("hashedPassword"), []byte("salt"), nil
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
				mock.EXPECT().Get(passwordMinLengthSetting).Return(&v3.Setting{
					Value: "10",
				}, nil)

				return mock
			},
			mockUserCache: func() ctrlv3.UserCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
				mock.EXPECT().Get("test-user").Return(fakeUser, nil)

				return mock
			},

			wantAllowed: false,
		},
		"password is the same as the user name": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Namespace:       localUserPasswordsNamespace,
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "password"},
					Object: runtime.RawExtension{
						Raw: rawSecret,
					},
				},
			},
			hasher: func(_ string) ([]byte, []byte, error) {
				return []byte("hashedPassword"), []byte("salt"), nil
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
				mock.EXPECT().Get(passwordMinLengthSetting).Return(&v3.Setting{
					Value: "5",
				}, nil)

				return mock
			},
			mockUserCache: func() ctrlv3.UserCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
				mock.EXPECT().Get("test-user").Return(fakeUser, nil)

				return mock
			},
			wantAllowed: false,
		},
		"error creating hashed password": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Namespace:       localUserPasswordsNamespace,
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object: runtime.RawExtension{
						Raw: rawSecret,
					},
				},
			},
			hasher: func(_ string) ([]byte, []byte, error) {
				return nil, nil, fmt.Errorf("unexpected error")
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
				mock.EXPECT().Get(passwordMinLengthSetting).Return(&v3.Setting{
					Value: "5",
				}, nil)

				return mock
			},
			mockUserCache: func() ctrlv3.UserCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
				mock.EXPECT().Get("test-user").Return(fakeUser, nil)

				return mock
			},
			wantErr: "unexpected error",
		},
		"user doesn't exist": {
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Namespace:       localUserPasswordsNamespace,
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object: runtime.RawExtension{
						Raw: rawSecret,
					},
				},
			},
			hasher: func(_ string) ([]byte, []byte, error) {
				return []byte("hashedPassword"), []byte("salt"), nil
			},
			mockSettingsCache: func() ctrlv3.SettingCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
			},
			mockUserCache: func() ctrlv3.UserCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
				mock.EXPECT().Get("test-user").Return(nil, apierrors.NewNotFound(schema.GroupResource{}, ""))

				return mock
			},
			wantAllowed: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := Mutator{
				hasher:       test.hasher,
				settingCache: test.mockSettingsCache(),
				userCache:    test.mockUserCache(),
			}

			response, err := m.Admit(test.request)

			if test.wantErr != "" {
				assert.EqualError(t, err, test.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.wantAllowed, response.Allowed)
				if test.wantPatch != "" {
					var wantPatch []interface{}
					err = json.Unmarshal([]byte(test.wantPatch), &wantPatch)
					assert.NoError(t, err)
					var patch []interface{}
					err = json.Unmarshal(response.Patch, &patch)
					assert.NoError(t, err)
					sortPatch(patch)
					sortPatch(wantPatch)
					assert.Equal(t, wantPatch, patch)
				} else {
					assert.Nil(t, response.Patch)
				}
			}
		})
	}
}

func sortPatch(patch []interface{}) {
	sort.Slice(patch, func(i, j int) bool {
		pi := patch[i].(map[string]interface{})
		pj := patch[j].(map[string]interface{})
		return fmt.Sprint(pi["path"]) < fmt.Sprint(pj["path"])
	})
}
