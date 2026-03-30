package secret

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
)

func TestCloudCredentialAdmit(t *testing.T) {
	const secretName = "cc-test-credential-12345"
	tests := []struct {
		name           string
		secretType     corev1.SecretType
		secretData     map[string][]byte
		namespace      string
		operation      admissionv1.Operation
		dynamicSchema  *v3.DynamicSchema
		schemaNotFound bool
		schemaError    error
		featureEnabled bool
		wantAdmit      bool
		wantError      bool
		wantMessage    string
	}{
		{
			name:       "valid amazon credential with all required fields",
			secretType: corev1.SecretType(TypePrefix + "amazonec2"),
			namespace:  CredentialNamespace,
			secretData: map[string][]byte{
				"accessKey":     []byte("AKIAIOSFODNN7EXAMPLE"),
				"secretKey":     []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
				"defaultRegion": []byte("us-east-1"),
			},
			dynamicSchema: &v3.DynamicSchema{
				ObjectMeta: metav1.ObjectMeta{
					Name: "amazonec2credentialconfig",
				},
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"accessKey":     {Required: true},
						"secretKey":     {Required: true},
						"defaultRegion": {Required: false},
					},
				},
			},
			wantAdmit: true,
		},
		{
			name:       "missing required field",
			secretType: corev1.SecretType(TypePrefix + "amazonec2"),
			namespace:  CredentialNamespace,
			secretData: map[string][]byte{
				"accessKey": []byte("AKIAIOSFODNN7EXAMPLE"),
				// secretKey is missing
			},
			dynamicSchema: &v3.DynamicSchema{
				ObjectMeta: metav1.ObjectMeta{
					Name: "amazonec2credentialconfig",
				},
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"accessKey": {Required: true},
						"secretKey": {Required: true},
					},
				},
			},
			wantAdmit:   false,
			wantMessage: `required field "secretKey" is missing`,
		},
		{
			name:       "field too short",
			secretType: corev1.SecretType(TypePrefix + "digitalocean"),
			namespace:  CredentialNamespace,
			secretData: map[string][]byte{
				"accessToken": []byte("abc"),
			},
			dynamicSchema: &v3.DynamicSchema{
				ObjectMeta: metav1.ObjectMeta{
					Name: "digitaloceancredentialconfig",
				},
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"accessToken": {Required: true, MinLength: 10},
					},
				},
			},
			wantAdmit:   false,
			wantMessage: `field "accessToken" must be at least 10 characters`,
		},
		{
			name:       "field too long",
			secretType: corev1.SecretType(TypePrefix + "digitalocean"),
			namespace:  CredentialNamespace,
			secretData: map[string][]byte{
				"accessToken": []byte("this-is-a-very-long-token-that-exceeds-the-max-length"),
			},
			dynamicSchema: &v3.DynamicSchema{
				ObjectMeta: metav1.ObjectMeta{
					Name: "digitaloceancredentialconfig",
				},
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"accessToken": {Required: true, MaxLength: 20},
					},
				},
			},
			wantAdmit:   false,
			wantMessage: `field "accessToken" must be at most 20 characters`,
		},
		{
			name:       "invalid option value",
			secretType: corev1.SecretType(TypePrefix + "amazonec2"),
			namespace:  CredentialNamespace,
			secretData: map[string][]byte{
				"region": []byte("invalid-region"),
			},
			dynamicSchema: &v3.DynamicSchema{
				ObjectMeta: metav1.ObjectMeta{
					Name: "amazonec2credentialconfig",
				},
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"region": {Required: false, Options: []string{"us-east-1", "us-west-2", "eu-west-1"}},
					},
				},
			},
			wantAdmit:   false,
			wantMessage: `field "region" must be one of: us-east-1, us-west-2, eu-west-1`,
		},
		{
			name:       "generic type skips validation",
			secretType: corev1.SecretType(TypePrefix + "generic"),
			namespace:  CredentialNamespace,
			secretData: map[string][]byte{
				"any-field": []byte("any-value"),
			},
			featureEnabled: true,
			wantAdmit:      true,
		},
		{
			name:       "x- prefixed generic type skips validation",
			secretType: corev1.SecretType(TypePrefix + "x-custom-provider"),
			namespace:  CredentialNamespace,
			secretData: map[string][]byte{
				"apiKey": []byte("some-key"),
			},
			featureEnabled: true,
			wantAdmit:      true,
		},
		{
			name:           "no schema found - treat as generic",
			secretType:     corev1.SecretType(TypePrefix + "unknownprovider"),
			namespace:      CredentialNamespace,
			schemaNotFound: true,
			featureEnabled: true,
			secretData: map[string][]byte{
				"someKey": []byte("some-value"),
			},
			wantAdmit:   false,
			wantMessage: `credential type "unknownprovider" has no corresponding DynamicSchema; only "x-"-prefixed generic types are allowed when "generic-cloud-credentials" is enabled`,
		},
		{
			name:           "generic type denied when feature disabled",
			secretType:     corev1.SecretType(TypePrefix + "generic"),
			namespace:      CredentialNamespace,
			schemaNotFound: true,
			featureEnabled: false,
			secretData: map[string][]byte{
				"someKey": []byte("some-value"),
			},
			wantAdmit:   false,
			wantMessage: `credential type "generic" has no corresponding DynamicSchema and the "generic-cloud-credentials" feature is not enabled`,
		},
		{
			name:           "x- type denied when feature disabled",
			secretType:     corev1.SecretType(TypePrefix + "x-custom-provider"),
			namespace:      CredentialNamespace,
			schemaNotFound: true,
			featureEnabled: false,
			secretData: map[string][]byte{
				"apiKey": []byte("some-key"),
			},
			wantAdmit:   false,
			wantMessage: `credential type "x-custom-provider" has no corresponding DynamicSchema and the "generic-cloud-credentials" feature is not enabled`,
		},
		{
			name:        "schema lookup error",
			secretType:  corev1.SecretType(TypePrefix + "amazonec2"),
			namespace:   CredentialNamespace,
			schemaError: apierrors.NewInternalError(assert.AnError),
			secretData: map[string][]byte{
				"accessKey": []byte("AKIAIOSFODNN7EXAMPLE"),
			},
			wantError: true,
		},
		{
			name:       "extra fields allowed (not in schema)",
			secretType: corev1.SecretType(TypePrefix + "amazonec2"),
			namespace:  CredentialNamespace,
			secretData: map[string][]byte{
				"accessKey":   []byte("AKIAIOSFODNN7EXAMPLE"),
				"extraField":  []byte("extra-value"),
				"customField": []byte("custom-value"),
			},
			dynamicSchema: &v3.DynamicSchema{
				ObjectMeta: metav1.ObjectMeta{
					Name: "amazonec2credentialconfig",
				},
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"accessKey": {Required: true},
					},
				},
			},
			wantAdmit: true,
		},
		{
			name:       "empty required field value",
			secretType: corev1.SecretType(TypePrefix + "amazonec2"),
			namespace:  CredentialNamespace,
			secretData: map[string][]byte{
				"accessKey": []byte(""),
			},
			dynamicSchema: &v3.DynamicSchema{
				ObjectMeta: metav1.ObjectMeta{
					Name: "amazonec2credentialconfig",
				},
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"accessKey": {Required: true},
					},
				},
			},
			wantAdmit:   false,
			wantMessage: `required field "accessKey" is missing`,
		},
		{
			name:        "empty credType - type prefix with no suffix",
			secretType:  corev1.SecretType(TypePrefix),
			namespace:   CredentialNamespace,
			secretData:  map[string][]byte{},
			wantAdmit:   false,
			wantMessage: "cloud credential secret type is missing the provider type suffix",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			secret := corev1.Secret{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: test.namespace,
				},
				Type: test.secretType,
				Data: test.secretData,
			}

			secretGVR := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
			secretGVK := metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
			secretJSON, err := json.Marshal(secret)
			require.NoError(t, err)

			operation := test.operation
			if operation == "" {
				operation = admissionv1.Create
			}

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:             "test-uid",
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					Name:            secretName,
					Namespace:       test.namespace,
					Operation:       operation,
					UserInfo:        v1authentication.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{Raw: secretJSON},
				},
			}

			dynamicSchemaCache := fake.NewMockNonNamespacedCacheInterface[*v3.DynamicSchema](ctrl)
			featureCache := createMockFeatureCache(ctrl, common.GenericCloudCredentialsFeatureName, test.featureEnabled)
			provClusterCache := fake.NewMockCacheInterface[*provv1.Cluster](ctrl)

			// Only set up expectations if we need to query the schema
			if operation != admissionv1.Delete &&
				test.namespace == CredentialNamespace &&
				len(string(test.secretType)) > len(TypePrefix) {

				credType := string(test.secretType)[len(TypePrefix):]
				schemaName := credType + CredentialConfigSuffix

				switch {
				case test.schemaNotFound:
					dynamicSchemaCache.EXPECT().Get(schemaName).Return(nil, apierrors.NewNotFound(schema.GroupResource{
						Group:    "management.cattle.io",
						Resource: "dynamicschemas",
					}, schemaName))
				case test.schemaError != nil:
					dynamicSchemaCache.EXPECT().Get(schemaName).Return(nil, test.schemaError)
				case test.dynamicSchema != nil:
					dynamicSchemaCache.EXPECT().Get(schemaName).Return(test.dynamicSchema, nil)
				case strings.HasPrefix(string(test.secretType), TypePrefix):
					dynamicSchemaCache.EXPECT().Get(schemaName).Return(nil, apierrors.NewNotFound(schema.GroupResource{
						Group:    "management.cattle.io",
						Resource: "dynamicschemas",
					}, schemaName))
				}
			}

			provClusterCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()

			admitter := &cloudCredentialAdmitter{
				dynamicSchemaCache: dynamicSchemaCache,
				featureCache:       featureCache,
				provClusterCache:   provClusterCache,
			}
			response, err := admitter.AdmitCloudCredential(&secret, &req)

			if test.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.wantAdmit, response.Allowed)

			if !test.wantAdmit && test.wantMessage != "" {
				require.NotNil(t, response.Result)
				assert.Contains(t, response.Result.Message, test.wantMessage)
			}
		})
	}
}

func TestValidateSecretAgainstSchema(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string][]byte
		credType  string
		schema    *v3.DynamicSchema
		wantError string
	}{
		{
			name: "all required fields present",
			data: map[string][]byte{
				"field1": []byte("value1"),
				"field2": []byte("value2"),
			},
			credType: "test",
			schema: &v3.DynamicSchema{
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"field1": {Required: true},
						"field2": {Required: true},
					},
				},
			},
			wantError: "",
		},
		{
			name: "missing required field",
			data: map[string][]byte{
				"field1": []byte("value1"),
			},
			credType: "test",
			schema: &v3.DynamicSchema{
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"field1": {Required: true},
						"field2": {Required: true},
					},
				},
			},
			wantError: `required field "field2" is missing`,
		},
		{
			name: "optional field missing is ok",
			data: map[string][]byte{
				"field1": []byte("value1"),
			},
			credType: "test",
			schema: &v3.DynamicSchema{
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"field1": {Required: true},
						"field2": {Required: false},
					},
				},
			},
			wantError: "",
		},
		{
			name: "min length validation",
			data: map[string][]byte{
				"token": []byte("abc"),
			},
			credType: "test",
			schema: &v3.DynamicSchema{
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"token": {MinLength: 10},
					},
				},
			},
			wantError: `field "token" must be at least 10 characters`,
		},
		{
			name: "max length validation",
			data: map[string][]byte{
				"token": []byte("this-is-a-very-long-token"),
			},
			credType: "test",
			schema: &v3.DynamicSchema{
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"token": {MaxLength: 10},
					},
				},
			},
			wantError: `field "token" must be at most 10 characters`,
		},
		{
			name: "options validation - valid option",
			data: map[string][]byte{
				"region": []byte("us-east-1"),
			},
			credType: "test",
			schema: &v3.DynamicSchema{
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"region": {Options: []string{"us-east-1", "us-west-2"}},
					},
				},
			},
			wantError: "",
		},
		{
			name: "options validation - invalid option",
			data: map[string][]byte{
				"region": []byte("invalid-region"),
			},
			credType: "test",
			schema: &v3.DynamicSchema{
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"region": {Options: []string{"us-east-1", "us-west-2"}},
					},
				},
			},
			wantError: `field "region" must be one of: us-east-1, us-west-2`,
		},
		{
			name: "unknown fields are allowed",
			data: map[string][]byte{
				"field1":       []byte("value1"),
				"unknownField": []byte("unknown"),
			},
			credType: "test",
			schema: &v3.DynamicSchema{
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"field1": {Required: true},
					},
				},
			},
			wantError: "",
		},
		{
			name: "non-schema fields are ignored",
			data: map[string][]byte{
				"field1":         []byte("value1"),
				"someOtherField": []byte("ignored"),
			},
			credType: "test",
			schema: &v3.DynamicSchema{
				Spec: v3.DynamicSchemaSpec{
					ResourceFields: map[string]v3.Field{
						"field1": {Required: true},
					},
				},
			},
			wantError: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSecretAgainstSchema(test.data, test.schema)
			if test.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			}
		})
	}
}

func TestCloudCredentialAdmitDelete(t *testing.T) {
	const secretName = "cc-test-credential-12345"

	tests := []struct {
		name                     string
		gracePeriodSeconds       *int64
		clustersByCloudCred      []*provv1.Cluster
		clustersByCloudCredErr   error
		clustersByMachinePool    []*provv1.Cluster
		clustersByMachinePoolErr error
		clustersByEtcdS3         []*provv1.Cluster
		clustersByEtcdS3Err      error
		wantAdmit                bool
		wantError                bool
		wantMessage              string
	}{
		{
			name:      "DELETE allowed when credential is not in use",
			wantAdmit: true,
		},
		{
			name: "DELETE denied when credential is referenced by a provisioning cluster",
			clustersByCloudCred: []*provv1.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cluster",
						Namespace: "fleet-default",
					},
					Spec: provv1.ClusterSpec{
						CloudCredentialSecretName: CredentialNamespace + ":" + secretName,
					},
				},
			},
			wantAdmit:   false,
			wantMessage: "cloud credential is currently referenced by provisioning cluster fleet-default/test-cluster",
		},
		{
			name: "DELETE denied when credential is referenced by a machine pool",
			clustersByMachinePool: []*provv1.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pool-cluster",
						Namespace: "fleet-default",
					},
					Spec: provv1.ClusterSpec{
						RKEConfig: &provv1.RKEConfig{
							MachinePools: []provv1.RKEMachinePool{
								{
									RKECommonNodeConfig: rkev1.RKECommonNodeConfig{
										CloudCredentialSecretName: CredentialNamespace + ":" + secretName,
									},
								},
							},
						},
					},
				},
			},
			wantAdmit:   false,
			wantMessage: "cloud credential is currently referenced by a machine pool in provisioning cluster fleet-default/pool-cluster",
		},
		{
			name:               "force-delete bypasses in-use check",
			gracePeriodSeconds: ptr.To[int64](0),
			clustersByCloudCred: []*provv1.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cluster",
						Namespace: "fleet-default",
					},
					Spec: provv1.ClusterSpec{
						CloudCredentialSecretName: CredentialNamespace + ":" + secretName,
					},
				},
			},
			wantAdmit: true,
		},
		{
			name:               "non-zero GracePeriodSeconds does not bypass in-use check",
			gracePeriodSeconds: ptr.To[int64](30),
			clustersByCloudCred: []*provv1.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cluster",
						Namespace: "fleet-default",
					},
					Spec: provv1.ClusterSpec{
						CloudCredentialSecretName: CredentialNamespace + ":" + secretName,
					},
				},
			},
			wantAdmit:   false,
			wantMessage: "cloud credential is currently referenced by provisioning cluster fleet-default/test-cluster",
		},
		{
			name: "DELETE denied when credential is referenced by etcd s3 config",
			clustersByEtcdS3: []*provv1.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "s3-cluster",
						Namespace: "fleet-default",
					},
					Spec: provv1.ClusterSpec{
						RKEConfig: &provv1.RKEConfig{
							ClusterConfiguration: rkev1.ClusterConfiguration{
								ETCD: &rkev1.ETCD{
									S3: &rkev1.ETCDSnapshotS3{
										CloudCredentialName: CredentialNamespace + ":" + secretName,
									},
								},
							},
						},
					},
				},
			},
			wantAdmit:   false,
			wantMessage: "cloud credential is currently referenced by etcd s3 config in provisioning cluster fleet-default/s3-cluster",
		},
		{
			name:                   "error checking cluster-level references",
			clustersByCloudCredErr: fmt.Errorf("index error"),
			wantError:              true,
		},
		{
			name:                     "error checking machine pool references",
			clustersByMachinePoolErr: fmt.Errorf("index error"),
			wantError:                true,
		},
		{
			name:                "error checking etcd s3 references",
			clustersByEtcdS3Err: fmt.Errorf("index error"),
			wantError:           true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			secret := corev1.Secret{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: CredentialNamespace,
				},
				Type: corev1.SecretType(TypePrefix + "amazonec2"),
			}

			secretGVR := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
			secretGVK := metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
			secretJSON, err := json.Marshal(secret)
			require.NoError(t, err)

			deleteOpts := metav1.DeleteOptions{}
			if test.gracePeriodSeconds != nil {
				deleteOpts.GracePeriodSeconds = test.gracePeriodSeconds
			}
			deleteOptsJSON, err := json.Marshal(deleteOpts)
			require.NoError(t, err)

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:             "test-uid",
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					Name:            secretName,
					Namespace:       CredentialNamespace,
					Operation:       admissionv1.Delete,
					UserInfo:        v1authentication.UserInfo{Username: "test-user", UID: ""},
					OldObject:       runtime.RawExtension{Raw: secretJSON},
					Options:         runtime.RawExtension{Raw: deleteOptsJSON},
				},
			}

			provClusterCache := fake.NewMockCacheInterface[*provv1.Cluster](ctrl)
			provClusterCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()

			// Only set up index expectations if not force-delete
			isForce := test.gracePeriodSeconds != nil && *test.gracePeriodSeconds == 0
			if !isForce {
				provClusterCache.EXPECT().GetByIndex(byCloudCred, secretName).
					Return(test.clustersByCloudCred, test.clustersByCloudCredErr)

				// Only expect machine pool check if cluster-level check passed
				if test.clustersByCloudCredErr == nil && len(test.clustersByCloudCred) == 0 {
					provClusterCache.EXPECT().GetByIndex(byMachinePoolCloudCred, secretName).
						Return(test.clustersByMachinePool, test.clustersByMachinePoolErr)
				}

				if test.clustersByCloudCredErr == nil && len(test.clustersByCloudCred) == 0 &&
					test.clustersByMachinePoolErr == nil && len(test.clustersByMachinePool) == 0 {
					provClusterCache.EXPECT().GetByIndex(byEtcdS3CloudCred, secretName).
						Return(test.clustersByEtcdS3, test.clustersByEtcdS3Err)
				}
			}

			dynamicSchemaCache := fake.NewMockNonNamespacedCacheInterface[*v3.DynamicSchema](ctrl)
			featureCache := createMockFeatureCache(ctrl, common.GenericCloudCredentialsFeatureName, true)

			admitter := &cloudCredentialAdmitter{
				dynamicSchemaCache: dynamicSchemaCache,
				featureCache:       featureCache,
				provClusterCache:   provClusterCache,
			}

			response, err := admitter.AdmitCloudCredential(&secret, &req)

			if test.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.wantAdmit, response.Allowed)

			if !test.wantAdmit && test.wantMessage != "" {
				require.NotNil(t, response.Result)
				assert.Contains(t, response.Result.Message, test.wantMessage)
			}
		})
	}
}

func createMockFeatureCache(ctrl *gomock.Controller, featureName string, enabled bool) *fake.MockNonNamespacedCacheInterface[*v3.Feature] {
	featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
	featureCache.EXPECT().Get(featureName).DoAndReturn(func(string) (*v3.Feature, error) {
		return &v3.Feature{
			Spec: v3.FeatureSpec{
				Value: &enabled,
			},
		}, nil
	}).AnyTimes()
	return featureCache
}

func TestByCloudCredentialIndex(t *testing.T) {
	tests := []struct {
		name    string
		cluster *provv1.Cluster
		want    []string
	}{
		{
			name: "cluster with cloud credential",
			cluster: &provv1.Cluster{
				Spec: provv1.ClusterSpec{
					CloudCredentialSecretName: "cattle-cloud-credentials:cc-my-credential",
				},
			},
			want: []string{"cc-my-credential"},
		},
		{
			name: "cluster with legacy cloud credential name",
			cluster: &provv1.Cluster{
				Spec: provv1.ClusterSpec{
					CloudCredentialSecretName: "cc-my-legacy-credential",
				},
			},
			want: []string{"cc-my-legacy-credential"},
		},
		{
			name: "cluster with malformed namespaced credential",
			cluster: &provv1.Cluster{
				Spec: provv1.ClusterSpec{
					CloudCredentialSecretName: "cattle-cloud-credentials:",
				},
			},
			want: nil,
		},
		{
			name: "cluster without cloud credential",
			cluster: &provv1.Cluster{
				Spec: provv1.ClusterSpec{},
			},
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := byCloudCredentialIndex(test.cluster)
			require.NoError(t, err)
			assert.Equal(t, test.want, result)
		})
	}
}

func TestByMachinePoolCloudCredIndex(t *testing.T) {
	tests := []struct {
		name    string
		cluster *provv1.Cluster
		want    []string
	}{
		{
			name: "cluster with machine pool cloud credentials",
			cluster: &provv1.Cluster{
				Spec: provv1.ClusterSpec{
					RKEConfig: &provv1.RKEConfig{
						MachinePools: []provv1.RKEMachinePool{
							{
								RKECommonNodeConfig: rkev1.RKECommonNodeConfig{
									CloudCredentialSecretName: "cattle-cloud-credentials:cc-pool-cred-1",
								},
							},
							{
								RKECommonNodeConfig: rkev1.RKECommonNodeConfig{
									CloudCredentialSecretName: "cattle-cloud-credentials:cc-pool-cred-2",
								},
							},
						},
					},
				},
			},
			want: []string{"cc-pool-cred-1", "cc-pool-cred-2"},
		},
		{
			name: "cluster with duplicate machine pool credentials",
			cluster: &provv1.Cluster{
				Spec: provv1.ClusterSpec{
					RKEConfig: &provv1.RKEConfig{
						MachinePools: []provv1.RKEMachinePool{
							{
								RKECommonNodeConfig: rkev1.RKECommonNodeConfig{
									CloudCredentialSecretName: "cattle-cloud-credentials:cc-same-cred",
								},
							},
							{
								RKECommonNodeConfig: rkev1.RKECommonNodeConfig{
									CloudCredentialSecretName: "cattle-cloud-credentials:cc-same-cred",
								},
							},
						},
					},
				},
			},
			want: []string{"cc-same-cred"},
		},
		{
			name: "cluster with no RKEConfig",
			cluster: &provv1.Cluster{
				Spec: provv1.ClusterSpec{},
			},
			want: nil,
		},
		{
			name: "cluster with empty machine pools",
			cluster: &provv1.Cluster{
				Spec: provv1.ClusterSpec{
					RKEConfig: &provv1.RKEConfig{
						MachinePools: []provv1.RKEMachinePool{
							{},
						},
					},
				},
			},
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := byMachinePoolCloudCredIndex(test.cluster)
			require.NoError(t, err)
			assert.Equal(t, test.want, result)
		})
	}
}
