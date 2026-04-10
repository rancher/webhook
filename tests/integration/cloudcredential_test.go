package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// CredentialNamespace is the namespace where CloudCredential secrets are stored
	CredentialNamespace = "cattle-cloud-credentials"

	// TypePrefix is the prefix for cloud credential secret types
	TypePrefix = "rke.cattle.io/cloud-credential-"
)

// TestCloudCredentialValidation tests various flows of cloud credential creation, update, and deletion
func (m *IntegrationSuite) TestCloudCredentialValidation() {
	// Ensure cloud credentials namespace exists
	m.ensureNamespace(CredentialNamespace)

	tests := []struct {
		name     string
		testFunc func(t *testing.T, suffix string)
	}{
		{
			name:     "valid credential creation with all required fields",
			testFunc: m.testValidCredentialCreation,
		},
		{
			name:     "invalid credential creation - missing required field",
			testFunc: m.testInvalidCredentialMissingField,
		},
		{
			name:     "cloud credential-like secret with wrong type is allowed",
			testFunc: m.testWrongTypeBypassesCloudCredentialValidation,
		},
		{
			name:     "cloud credential-like secret with wrong namespace is allowed",
			testFunc: m.testWrongNamespaceBypassesCloudCredentialValidation,
		},
		{
			name:     "credential deletion allowed when not in use",
			testFunc: m.testCredentialDeletionNotInUse,
		},
		{
			name:     "credential deletion blocked when referenced by provisioning cluster",
			testFunc: m.testCredentialDeletionBlockedByCluster,
		},
		{
			name:     "credential deletion blocked when referenced by machine pool",
			testFunc: m.testCredentialDeletionBlockedByMachinePool,
		},
		{
			name:     "credential deletion blocked when referenced by etcd s3 config",
			testFunc: m.testCredentialDeletionBlockedByEtcdS3,
		},
		{
			name:     "credential deletion allowed with force-delete",
			testFunc: m.testCredentialForceDeletion,
		},
	}

	for i, tt := range tests {
		tt := tt
		suffix := fmt.Sprintf("%d", i) // unique suffix for the sub-test
		m.Run(tt.name, func() {
			tt.testFunc(m.T(), suffix)
		})
	}
}

// testValidCredentialCreation verifies a valid credential with all required fields is created successfully
func (m *IntegrationSuite) testValidCredentialCreation(t *testing.T, suffix string) {
	// Create a valid credential
	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-amazonec2-credential-" + m.testnamespace + "-" + suffix,
			Namespace: CredentialNamespace,
		},
		Type: corev1.SecretType(TypePrefix + "amazonec2"),
		StringData: map[string]string{
			"accessKey":     "AKIAIOSFODNN7EXAMPLE",
			"secretKey":     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"defaultRegion": "us-east-1",
		},
	}

	objGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := &corev1.Secret{}
	err = client.Create(ctx, credential.Namespace, credential, result, metav1.CreateOptions{})
	m.NoError(err, "Valid credential creation should succeed")
	m.Equal(credential.Name, result.Name)
}

// testInvalidCredentialMissingField verifies credential creation fails when required field is missing
func (m *IntegrationSuite) testInvalidCredentialMissingField(t *testing.T, suffix string) {
	// Create credential without required field
	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-digitalocean-missing-field-" + m.testnamespace + "-" + suffix,
			Namespace: CredentialNamespace,
		},
		Type: corev1.SecretType(TypePrefix + "digitalocean"),
		StringData: map[string]string{
			"region": "nyc3",
			// accessToken is missing but required
		},
	}

	objGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := &corev1.Secret{}
	err = client.Create(ctx, credential.Namespace, credential, result, metav1.CreateOptions{})
	m.Error(err, "Credential with missing required field should fail")
	m.assertCloudCredentialValidationError(err, "required field")
}

func (m *IntegrationSuite) assertCloudCredentialValidationError(err error, detailFragment string) {
	m.Require().Error(err)
	errMsg := err.Error()
	// Keep this check broad enough to survive kubernetes error formatting changes.
	m.Contains(errMsg, "admission webhook")
	m.Contains(errMsg, detailFragment)
}

// testWrongTypeBypassesCloudCredentialValidation verifies webhook allows secrets in the cloud credential
// namespace when the type does not have the cloud credential prefix.
func (m *IntegrationSuite) testWrongTypeBypassesCloudCredentialValidation(t *testing.T, suffix string) {
	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cc-wrong-type-" + m.testnamespace + "-" + suffix,
			Namespace: CredentialNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			// Deliberately missing dynamic schema fields for a cloud provider.
			"region": "nyc3",
		},
	}

	objGVK := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := &corev1.Secret{}
	err = client.Create(ctx, credential.Namespace, credential, result, metav1.CreateOptions{})
	m.NoError(err, "Secret in cloud credential namespace with non-cloud type should be allowed")
	m.Equal(credential.Name, result.Name)
}

// testWrongNamespaceBypassesCloudCredentialValidation verifies webhook allows secrets with a cloud
// credential type prefix when they are outside the cloud credential namespace.
func (m *IntegrationSuite) testWrongNamespaceBypassesCloudCredentialValidation(t *testing.T, suffix string) {
	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cc-wrong-namespace-" + m.testnamespace + "-" + suffix,
			Namespace: m.testnamespace,
		},
		Type: corev1.SecretType(TypePrefix + "digitalocean"),
		StringData: map[string]string{
			// Deliberately missing required accessToken for digitalocean schema.
			"region": "nyc3",
		},
	}

	objGVK := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := &corev1.Secret{}
	err = client.Create(ctx, credential.Namespace, credential, result, metav1.CreateOptions{})
	m.NoError(err, "Secret with cloud credential type outside cloud credential namespace should be allowed")
	m.Equal(credential.Name, result.Name)
}

// testCredentialDeletionNotInUse verifies credential can be deleted when not referenced by any cluster
func (m *IntegrationSuite) testCredentialDeletionNotInUse(t *testing.T, suffix string) {
	// Create a credential
	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deletion-notinuse-" + m.testnamespace + "-" + suffix,
			Namespace: CredentialNamespace,
		},
		Type: corev1.SecretType(TypePrefix + "amazonec2"),
		StringData: map[string]string{
			"accessKey": "AKIAIOSFODNN7EXAMPLE",
			"secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	objGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := &corev1.Secret{}
	err = client.Create(ctx, credential.Namespace, credential, result, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create credential")

	// Delete the credential - should succeed since not in use
	err = client.Delete(ctx, credential.Namespace, credential.Name, metav1.DeleteOptions{})
	m.NoError(err, "Deletion of unused credential should succeed")
}

// testCredentialDeletionBlockedByCluster verifies credential deletion is blocked when referenced by a provisioning cluster
func (m *IntegrationSuite) testCredentialDeletionBlockedByCluster(t *testing.T, suffix string) {
	// Create a credential
	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deletion-blocked-cluster-" + m.testnamespace + "-" + suffix,
			Namespace: CredentialNamespace,
		},
		Type: corev1.SecretType(TypePrefix + "amazonec2"),
		StringData: map[string]string{
			"accessKey": "AKIAIOSFODNN7EXAMPLE",
			"secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	secretGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}
	secretClient, err := m.clientFactory.ForKind(secretGVK)
	m.Require().NoError(err, "Failed to create secret client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := &corev1.Secret{}
	err = secretClient.Create(ctx, credential.Namespace, credential, result, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create credential")

	// Create a provisioning cluster that references this credential
	cluster := &provv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-blocked-" + suffix,
			Namespace: m.testnamespace,
		},
		Spec: provv1.ClusterSpec{
			CloudCredentialSecretName: CredentialNamespace + ":" + credential.Name,
			KubernetesVersion:         "v1.34.1+rke2r1",
		},
	}

	clusterGVK := schema.GroupVersionKind{
		Group:   "provisioning.cattle.io",
		Version: "v1",
		Kind:    "Cluster",
	}
	clusterClient, err := m.clientFactory.ForKind(clusterGVK)
	m.Require().NoError(err, "Failed to create cluster client")

	clusterResult := &provv1.Cluster{}
	err = clusterClient.Create(ctx, cluster.Namespace, cluster, clusterResult, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create provisioning cluster")

	// Try to delete the credential - should fail since it's referenced by the cluster
	err = secretClient.Delete(ctx, credential.Namespace, credential.Name, metav1.DeleteOptions{})
	m.Error(err, "Deletion of in-use credential should fail")
}

// testCredentialDeletionBlockedByMachinePool verifies credential deletion is blocked when referenced by a machine pool
func (m *IntegrationSuite) testCredentialDeletionBlockedByMachinePool(t *testing.T, suffix string) {
	// Create a credential
	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deletion-blocked-machinepool-" + m.testnamespace + "-" + suffix,
			Namespace: CredentialNamespace,
		},
		Type: corev1.SecretType(TypePrefix + "amazonec2"),
		StringData: map[string]string{
			"accessKey": "AKIAIOSFODNN7EXAMPLE",
			"secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	secretGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}
	secretClient, err := m.clientFactory.ForKind(secretGVK)
	m.Require().NoError(err, "Failed to create secret client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := &corev1.Secret{}
	err = secretClient.Create(ctx, credential.Namespace, credential, result, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create credential")

	// Create a provisioning cluster with a machine pool that references this credential
	cluster := &provv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-machinepool-" + suffix,
			Namespace: m.testnamespace,
		},
		Spec: provv1.ClusterSpec{
			KubernetesVersion: "v1.34.1+rke2r1",
			RKEConfig: &provv1.RKEConfig{
				MachinePools: []provv1.RKEMachinePool{
					{
						Name:       "test-machine-pool-" + suffix,
						Quantity:   Ptr(int32(1)),
						NodeConfig: &corev1.ObjectReference{Name: "default"},
						RKECommonNodeConfig: rkev1.RKECommonNodeConfig{
							CloudCredentialSecretName: CredentialNamespace + ":" + credential.Name,
						},
					},
				},
			},
		},
	}

	clusterGVK := schema.GroupVersionKind{
		Group:   "provisioning.cattle.io",
		Version: "v1",
		Kind:    "Cluster",
	}
	clusterClient, err := m.clientFactory.ForKind(clusterGVK)
	m.Require().NoError(err, "Failed to create cluster client")

	clusterResult := &provv1.Cluster{}
	err = clusterClient.Create(ctx, cluster.Namespace, cluster, clusterResult, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create provisioning cluster")

	// Try to delete the credential - should fail since it's referenced by the machine pool
	err = secretClient.Delete(ctx, credential.Namespace, credential.Name, metav1.DeleteOptions{})
	m.Error(err, "Deletion of credential used by machine pool should fail")
}

// testCredentialDeletionBlockedByEtcdS3 verifies credential deletion is blocked when referenced by etcd s3 config
func (m *IntegrationSuite) testCredentialDeletionBlockedByEtcdS3(t *testing.T, suffix string) {
	// Create a credential
	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deletion-blocked-etcds3-" + m.testnamespace + "-" + suffix,
			Namespace: CredentialNamespace,
		},
		Type: corev1.SecretType(TypePrefix + "amazonec2"),
		StringData: map[string]string{
			"accessKey": "AKIAIOSFODNN7EXAMPLE",
			"secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	secretGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}
	secretClient, err := m.clientFactory.ForKind(secretGVK)
	m.Require().NoError(err, "Failed to create secret client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := &corev1.Secret{}
	err = secretClient.Create(ctx, credential.Namespace, credential, result, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create credential")

	// Create a dummy secret in the test namespace to satisfy provisioning cluster ETCD validation
	dummySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      credential.Name,
			Namespace: m.testnamespace,
		},
	}
	err = secretClient.Create(ctx, dummySecret.Namespace, dummySecret, &corev1.Secret{}, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create dummy etcd secret")

	// Create a provisioning cluster with etcd s3 backup that references this credential
	cluster := &provv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-etcds3-" + suffix,
			Namespace: m.testnamespace,
		},
		Spec: provv1.ClusterSpec{
			KubernetesVersion: "v1.34.1+rke2r1",
			RKEConfig: &provv1.RKEConfig{
				ClusterConfiguration: rkev1.ClusterConfiguration{
					ETCD: &rkev1.ETCD{
						S3: &rkev1.ETCDSnapshotS3{
							CloudCredentialName: credential.Name,
						},
					},
				},
			},
		},
	}

	clusterGVK := schema.GroupVersionKind{
		Group:   "provisioning.cattle.io",
		Version: "v1",
		Kind:    "Cluster",
	}
	clusterClient, err := m.clientFactory.ForKind(clusterGVK)
	m.Require().NoError(err, "Failed to create cluster client")

	clusterResult := &provv1.Cluster{}
	err = clusterClient.Create(ctx, cluster.Namespace, cluster, clusterResult, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create provisioning cluster")

	// Try to delete the credential - should fail since it's referenced by etcd s3 config
	err = secretClient.Delete(ctx, credential.Namespace, credential.Name, metav1.DeleteOptions{})
	m.Error(err, "Deletion of credential used by etcd s3 config should fail")
}

// testCredentialForceDeletion verifies credential can be force-deleted even when in use
func (m *IntegrationSuite) testCredentialForceDeletion(t *testing.T, suffix string) {
	// Create a credential
	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-forcedelete-credential-" + m.testnamespace + "-" + suffix,
			Namespace: CredentialNamespace,
		},
		Type: corev1.SecretType(TypePrefix + "amazonec2"),
		StringData: map[string]string{
			"accessKey": "AKIAIOSFODNN7EXAMPLE",
			"secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	secretGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}
	secretClient, err := m.clientFactory.ForKind(secretGVK)
	m.Require().NoError(err, "Failed to create secret client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := &corev1.Secret{}
	err = secretClient.Create(ctx, credential.Namespace, credential, result, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create credential")

	// Create a provisioning cluster that references this credential
	cluster := &provv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-forcedelete-" + suffix,
			Namespace: m.testnamespace,
		},
		Spec: provv1.ClusterSpec{
			CloudCredentialSecretName: CredentialNamespace + ":" + credential.Name,
			KubernetesVersion:         "v1.34.1+rke2r1",
		},
	}

	clusterGVK := schema.GroupVersionKind{
		Group:   "provisioning.cattle.io",
		Version: "v1",
		Kind:    "Cluster",
	}
	clusterClient, err := m.clientFactory.ForKind(clusterGVK)
	m.Require().NoError(err, "Failed to create cluster client")

	clusterResult := &provv1.Cluster{}
	err = clusterClient.Create(ctx, cluster.Namespace, cluster, clusterResult, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create provisioning cluster")

	// Force-delete the credential (GracePeriodSeconds=0) - should succeed even though in use
	gracePeriodSeconds := int64(0)
	err = secretClient.Delete(ctx, credential.Namespace, credential.Name, metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	})
	m.NoError(err, "Force-delete of in-use credential should succeed")
}

// ensureNamespace creates a namespace if it doesn't exist
func (m *IntegrationSuite) ensureNamespace(namespaceName string) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	}
	objGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Namespace",
	}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create namespace client")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to create - ignore error if it already exists
	_ = client.Create(ctx, "", ns, nil, metav1.CreateOptions{})
}
