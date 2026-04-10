package secret

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/cel-go/cel"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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

			dynamicSchemaCache := fake.NewMockNonNamespacedCacheInterface[*v3.DynamicSchema](ctrl)
			featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
			provClusterCache := fake.NewMockCacheInterface[*provv1.Cluster](ctrl)
			provClusterCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()

			validator := NewValidator(roleCache, roleBindingCache, dynamicSchemaCache, featureCache, provClusterCache)

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

func TestAdmitCloudCredentialDispatch(t *testing.T) {
	ctrl := gomock.NewController(t)

	secretGVR := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	secretGVK := metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cc-test-12345",
			Namespace: CredentialNamespace,
		},
		Type: corev1.SecretType(TypePrefix + "amazonec2"),
	}

	secretRaw, err := json.Marshal(secret)
	require.NoError(t, err)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:             "1",
			Kind:            secretGVK,
			Resource:        secretGVR,
			RequestKind:     &secretGVK,
			RequestResource: &secretGVR,
			Name:            secret.Name,
			Namespace:       secret.Namespace,
			Operation:       admissionv1.Create,
			UserInfo:        v1authentication.UserInfo{Username: "test-user"},
			Object:          runtime.RawExtension{Raw: secretRaw},
			OldObject:       runtime.RawExtension{},
		},
	}

	roleCache := fake.NewMockCacheInterface[*rbacv1.Role](ctrl)
	roleBindingCache := fake.NewMockCacheInterface[*rbacv1.RoleBinding](ctrl)
	roleCache.EXPECT().AddIndexer(roleOwnerIndex, gomock.Any())
	roleBindingCache.EXPECT().AddIndexer(roleBindingOwnerIndex, gomock.Any())

	dynamicSchemaCache := fake.NewMockNonNamespacedCacheInterface[*v3.DynamicSchema](ctrl)
	featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
	provClusterCache := fake.NewMockCacheInterface[*provv1.Cluster](ctrl)
	provClusterCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()

	// The cloud credential admitter will look up the dynamic schema for this type.
	dynamicSchemaCache.EXPECT().Get("amazonec2credentialconfig").Return(&v3.DynamicSchema{
		Spec: v3.DynamicSchemaSpec{
			ResourceFields: map[string]v3.Field{},
		},
	}, nil)

	validator := NewValidator(roleCache, roleBindingCache, dynamicSchemaCache, featureCache, provClusterCache)

	admitters := validator.Admitters()
	require.Len(t, admitters, 1)
	response, err := admitters[0].Admit(&req)
	require.NoError(t, err)
	assert.True(t, response.Allowed)
}

func TestAdmitNonDeleteNonCloudCredentialAllowed(t *testing.T) {
	ctrl := gomock.NewController(t)

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
	}

	secretRaw, err := json.Marshal(secret)
	require.NoError(t, err)

	secretGVR := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	secretGVK := metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:             "1",
			Kind:            secretGVK,
			Resource:        secretGVR,
			RequestKind:     &secretGVK,
			RequestResource: &secretGVR,
			Name:            secret.Name,
			Namespace:       secret.Namespace,
			Operation:       admissionv1.Create,
			UserInfo:        v1authentication.UserInfo{Username: "test-user"},
			Object:          runtime.RawExtension{Raw: secretRaw},
			OldObject:       runtime.RawExtension{},
		},
	}

	roleCache := fake.NewMockCacheInterface[*rbacv1.Role](ctrl)
	roleBindingCache := fake.NewMockCacheInterface[*rbacv1.RoleBinding](ctrl)
	roleCache.EXPECT().AddIndexer(roleOwnerIndex, gomock.Any())
	roleBindingCache.EXPECT().AddIndexer(roleBindingOwnerIndex, gomock.Any())

	dynamicSchemaCache := fake.NewMockNonNamespacedCacheInterface[*v3.DynamicSchema](ctrl)
	featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
	provClusterCache := fake.NewMockCacheInterface[*provv1.Cluster](ctrl)
	provClusterCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()

	validator := NewValidator(roleCache, roleBindingCache, dynamicSchemaCache, featureCache, provClusterCache)

	admitters := validator.Admitters()
	require.Len(t, admitters, 1)
	response, err := admitters[0].Admit(&req)
	require.NoError(t, err)
	assert.True(t, response.Allowed)
}

func TestIsCloudCredentialSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret *corev1.Secret
		want   bool
	}{
		{
			name: "cloud credential secret",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: CredentialNamespace},
				Type:       corev1.SecretType(TypePrefix + "amazonec2"),
			},
			want: true,
		},
		{
			name: "wrong namespace",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
				Type:       corev1.SecretType(TypePrefix + "amazonec2"),
			},
			want: false,
		},
		{
			name: "wrong type",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: CredentialNamespace},
				Type:       corev1.SecretType("Opaque"),
			},
			want: false,
		},
		{
			name: "wrong namespace and type",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
				Type:       corev1.SecretType("Opaque"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isCloudCredentialSecret(tt.secret))
		})
	}
}

func TestValidatorOperationsIncludeAll(t *testing.T) {
	ctrl := gomock.NewController(t)
	roleCache := fake.NewMockCacheInterface[*rbacv1.Role](ctrl)
	roleBindingCache := fake.NewMockCacheInterface[*rbacv1.RoleBinding](ctrl)
	roleCache.EXPECT().AddIndexer(roleOwnerIndex, gomock.Any())
	roleBindingCache.EXPECT().AddIndexer(roleBindingOwnerIndex, gomock.Any())

	dynamicSchemaCache := fake.NewMockNonNamespacedCacheInterface[*v3.DynamicSchema](ctrl)
	featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
	provClusterCache := fake.NewMockCacheInterface[*provv1.Cluster](ctrl)
	provClusterCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()

	validator := NewValidator(roleCache, roleBindingCache, dynamicSchemaCache, featureCache, provClusterCache)
	assert.ElementsMatch(t, []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
		admissionregistrationv1.Delete,
	}, validator.Operations())
}

func TestNewValidatorRegistersCloudCredentialIndexers(t *testing.T) {
	ctrl := gomock.NewController(t)
	roleCache := fake.NewMockCacheInterface[*rbacv1.Role](ctrl)
	roleBindingCache := fake.NewMockCacheInterface[*rbacv1.RoleBinding](ctrl)
	roleCache.EXPECT().AddIndexer(roleOwnerIndex, gomock.Any())
	roleBindingCache.EXPECT().AddIndexer(roleBindingOwnerIndex, gomock.Any())

	dynamicSchemaCache := fake.NewMockNonNamespacedCacheInterface[*v3.DynamicSchema](ctrl)
	featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
	provClusterCache := fake.NewMockCacheInterface[*provv1.Cluster](ctrl)

	var byCloudCredIndexer func(*provv1.Cluster) ([]string, error)
	var byMachinePoolCloudCredIndexer func(*provv1.Cluster) ([]string, error)
	var byEtcdS3CloudCredIndexer func(*provv1.Cluster) ([]string, error)

	provClusterCache.EXPECT().AddIndexer(byCloudCred, gomock.Any()).Do(func(_ string, fn func(*provv1.Cluster) ([]string, error)) {
		byCloudCredIndexer = fn
	})
	provClusterCache.EXPECT().AddIndexer(byMachinePoolCloudCred, gomock.Any()).Do(func(_ string, fn func(*provv1.Cluster) ([]string, error)) {
		byMachinePoolCloudCredIndexer = fn
	})
	provClusterCache.EXPECT().AddIndexer(byEtcdS3CloudCred, gomock.Any()).Do(func(_ string, fn func(*provv1.Cluster) ([]string, error)) {
		byEtcdS3CloudCredIndexer = fn
	})

	_ = NewValidator(roleCache, roleBindingCache, dynamicSchemaCache, featureCache, provClusterCache)

	require.NotNil(t, byCloudCredIndexer)
	require.NotNil(t, byMachinePoolCloudCredIndexer)
	require.NotNil(t, byEtcdS3CloudCredIndexer)

	cluster := &provv1.Cluster{Spec: provv1.ClusterSpec{CloudCredentialSecretName: "legacy-secret"}}
	keys, err := byCloudCredIndexer(cluster)
	require.NoError(t, err)
	assert.Equal(t, []string{"legacy-secret"}, keys)

	cluster.Spec.CloudCredentialSecretName = CredentialNamespace + ":cc-prod"
	keys, err = byCloudCredIndexer(cluster)
	require.NoError(t, err)
	assert.Equal(t, []string{"cc-prod"}, keys)

	cluster.Spec.CloudCredentialSecretName = CredentialNamespace + ":"
	keys, err = byCloudCredIndexer(cluster)
	require.NoError(t, err)
	assert.Nil(t, keys)

	cluster = &provv1.Cluster{Spec: provv1.ClusterSpec{RKEConfig: &provv1.RKEConfig{MachinePools: []provv1.RKEMachinePool{
		{RKECommonNodeConfig: rkev1.RKECommonNodeConfig{CloudCredentialSecretName: CredentialNamespace + ":cc-pool-a"}},
		{RKECommonNodeConfig: rkev1.RKECommonNodeConfig{CloudCredentialSecretName: "cc-pool-b"}},
		{RKECommonNodeConfig: rkev1.RKECommonNodeConfig{CloudCredentialSecretName: CredentialNamespace + ":"}},
	}}}}
	keys, err = byMachinePoolCloudCredIndexer(cluster)
	require.NoError(t, err)
	assert.Equal(t, []string{"cc-pool-a", "cc-pool-b"}, keys)

	cluster = &provv1.Cluster{Spec: provv1.ClusterSpec{RKEConfig: &provv1.RKEConfig{ClusterConfiguration: rkev1.ClusterConfiguration{ETCD: &rkev1.ETCD{S3: &rkev1.ETCDSnapshotS3{CloudCredentialName: CredentialNamespace + ":cc-s3"}}}}}}
	keys, err = byEtcdS3CloudCredIndexer(cluster)
	require.NoError(t, err)
	assert.Equal(t, []string{"cc-s3"}, keys)
}

func TestValidatingWebhookMatchConditionConfigured(t *testing.T) {
	webhooks := (&Validator{}).ValidatingWebhook(admissionregistrationv1.WebhookClientConfig{})
	require.Len(t, webhooks, 1)
	require.Len(t, webhooks[0].MatchConditions, 1)

	condition := webhooks[0].MatchConditions[0]
	assert.Equal(t, "delete-or-cloud-credential-only", condition.Name)
	assert.Equal(t, "request.operation == 'DELETE' || (object.type.startsWith('rke.cattle.io/cloud-credential-') && object.metadata.namespace == 'cattle-cloud-credentials')", condition.Expression)
}

func TestValidatingWebhookMatchConditionExpression(t *testing.T) {
	webhooks := (&Validator{}).ValidatingWebhook(admissionregistrationv1.WebhookClientConfig{})
	require.Len(t, webhooks, 1)
	require.Len(t, webhooks[0].MatchConditions, 1)

	expression := webhooks[0].MatchConditions[0].Expression

	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("request", cel.DynType),
	)
	require.NoError(t, err)

	ast, issues := env.Compile(expression)
	require.Nil(t, issues.Err())

	program, err := env.Program(ast)
	require.NoError(t, err)

	tests := []struct {
		name      string
		request   map[string]any
		object    map[string]any
		want      bool
		wantError bool
	}{
		{
			name:    "delete always matches",
			request: map[string]any{"operation": "DELETE"},
			want:    true,
		},
		{
			name:    "create cloud credential secret in expected namespace matches",
			request: map[string]any{"operation": "CREATE"},
			object: map[string]any{
				"type": TypePrefix + "amazonec2",
				"metadata": map[string]any{
					"namespace": CredentialNamespace,
				},
			},
			want: true,
		},
		{
			name:    "update cloud credential secret in expected namespace matches",
			request: map[string]any{"operation": "UPDATE"},
			object: map[string]any{
				"type": TypePrefix + "amazonec2",
				"metadata": map[string]any{
					"namespace": CredentialNamespace,
				},
			},
			want: true,
		},
		{
			name:    "create non cloud credential type does not match",
			request: map[string]any{"operation": "CREATE"},
			object: map[string]any{
				"type": corev1.SecretTypeOpaque,
				"metadata": map[string]any{
					"namespace": CredentialNamespace,
				},
			},
			want: false,
		},
		{
			name:    "create cloud credential type in wrong namespace does not match",
			request: map[string]any{"operation": "CREATE"},
			object: map[string]any{
				"type": TypePrefix + "amazonec2",
				"metadata": map[string]any{
					"namespace": "default",
				},
			},
			want: false,
		},
		{
			name:      "create with nil object returns evaluation error",
			request:   map[string]any{"operation": "CREATE"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			activation := map[string]any{
				"request": tt.request,
				"object":  tt.object,
			}

			result, _, err := program.Eval(activation)
			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			value, ok := result.Value().(bool)
			require.True(t, ok)
			assert.Equal(t, tt.want, value)
		})
	}
}
