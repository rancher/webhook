package integration_test

import (
	"context"
	"time"

	"github.com/rancher/webhook/pkg/resources/common"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (m *IntegrationSuite) TestSecretMutations() {
	objGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}

	tests := []struct {
		name          string
		secret        *v1.Secret
		expectMutated bool
	}{
		{
			name: "Cloud credential secret is mutated",
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cloud-credential-secret",
					Namespace: testNamespace,
				},
				Type: v1.SecretType("provisioning.cattle.io/cloud-credential"),
			},
			expectMutated: true,
		},
		{
			name: "Opaque secret is not mutated",
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-opaque-secret",
					Namespace: testNamespace,
				},
				Type: v1.SecretTypeOpaque,
				StringData: map[string]string{
					"username": "myuser",
					"password": "mypassword",
				},
			},
			expectMutated: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		m.Run(tt.name, func() {
			client, err := m.clientFactory.ForKind(objGVK)
			m.Require().NoError(err, "Failed to create client")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := &v1.Secret{}
			err = client.Create(ctx, tt.secret.Namespace, tt.secret, result, metav1.CreateOptions{})
			m.NoError(err, "Error creating secret")

			if tt.expectMutated {
				m.Contains(result.Annotations, common.CreatorIDAnn, "Expected secret to be mutated with creator annotation")
			} else {
				m.NotContains(result.Annotations, common.CreatorIDAnn, "Expected secret NOT to be mutated")
			}

			err = client.Delete(ctx, tt.secret.Namespace, tt.secret.Name, metav1.DeleteOptions{})
			m.NoError(err, "Error deleting secret")
		})
	}
}
