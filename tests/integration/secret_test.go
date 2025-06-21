package integration_test

import (
	"context"
	"time"

	"github.com/rancher/webhook/pkg/resources/common"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
					Namespace: m.testnamespace,
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
					Namespace: m.testnamespace,
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
		})
	}
}

// TestSecretDeleteMutation tests the mutation of RoleBindings when a secret is deleted.
// 1. Intercepts secret deletion requests
// 2. Finds any RoleBindings owned by the secret being deleted
// 3. Checks if these RoleBindings grant access to Roles that provide permissions to the secret
// 4. If found, redacts these Roles to only retain the "delete" permission

func (m *IntegrationSuite) TestSecretDeleteMutation() {
	// Setup GVK for Secret
	objGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}

	// Setup GVK for RoleBinding
	rbGVK := schema.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "RoleBinding",
	}

	// Setup GVK for Role
	roleGVK := schema.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "Role",
	}

	// 1. Create a client for each resource type
	secretClient, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create secret client")

	roleClient, err := m.clientFactory.ForKind(roleGVK)
	m.Require().NoError(err, "Failed to create role client")

	rbClient, err := m.clientFactory.ForKind(rbGVK)
	m.Require().NoError(err, "Failed to create rolebinding client")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 2. Create a test secret
	testSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-delete-secret",
			Namespace: m.testnamespace,
		},
		Type: v1.SecretTypeOpaque,
		StringData: map[string]string{
			"username": "testuser",
			"password": "testpass",
		},
	}

	secretResult := &v1.Secret{}
	err = secretClient.Create(ctx, testSecret.Namespace, testSecret, secretResult, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create test secret")

	// 3. Create a role that grants access to this secret
	testRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret-role",
			Namespace: m.testnamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{testSecret.Name},
				Verbs:         []string{"get", "update", "delete"},
			},
		},
	}

	roleResult := &rbacv1.Role{}
	err = roleClient.Create(ctx, testRole.Namespace, testRole, roleResult, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create test role")

	// 4. Create a rolebinding that references this role and is owned by the secret
	testRoleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret-rolebinding",
			Namespace: m.testnamespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Secret",
					Name:       testSecret.Name,
					UID:        secretResult.UID,
				},
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     testRole.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				APIGroup: "rbac.authorization.k8s.io",
				Name:     "test-user",
			},
		},
	}

	rbResult := &rbacv1.RoleBinding{}
	err = rbClient.Create(ctx, testRoleBinding.Namespace, testRoleBinding, rbResult, metav1.CreateOptions{})
	m.Require().NoError(err, "Failed to create test rolebinding")

	// 5. Delete the secret - this should trigger the webhook's admitDelete function
	err = secretClient.Delete(ctx, testSecret.Namespace, testSecret.Name, metav1.DeleteOptions{})
	m.Require().NoError(err, "Failed to delete test secret")

	// 6. Verify that the role was redacted to only include delete permission
	updatedRole := &rbacv1.Role{}
	err = roleClient.Get(ctx, testRole.Namespace, testRole.Name, updatedRole, metav1.GetOptions{})
	m.Require().NoError(err, "Failed to get updated role")

	// Check that the role now only has the delete verb
	m.Require().Len(updatedRole.Rules, 1, "Role should have exactly one rule")
	m.Require().Contains(updatedRole.Rules[0].Verbs, "delete", "Role should retain delete permission")
	m.Require().Len(updatedRole.Rules[0].Verbs, 1, "Role should only have delete permission")
}
