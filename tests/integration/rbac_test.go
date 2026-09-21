// RBAC Integration Tests
//
// These tests validate that the webhook ServiceAccount has the correct permissions.
// They automatically read the deployed ClusterRole and verify each permission.
//
// ## Extending the Tests
//
// The chart template (charts/rancher-webhook/templates/rbac.yaml) is the single source of truth.
// Most permissions are tested automatically by reading the deployed ClusterRole.
//
// ### Adding a New Validator/Mutator Resource
//
// 1. Add required permissions to charts/rancher-webhook/templates/rbac.yaml
// 2. TestWebhookRBAC will automatically test the new permissions
// 3. No test code changes needed for basic permission verification
//
// ### Adding a New Operation Test
//
// To test that the webhook can actually perform an operation (not just check permissions):
//
// 1. Add an entry to the operations slice in TestWebhookRBACActual
// 2. Define the operation function inline or as a helper
// 3. Set shouldErr=true if the webhook should NOT be able to perform the operation
//
// Example:
//
//	{
//	    name:      "CreateConfigMap",
//	    shouldErr: false,
//	    operation: func(ctx context.Context, webhookClient, _ *kubernetes.Clientset) error {
//	        cm := &corev1.ConfigMap{ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "default"}}
//	        _, err := webhookClient.CoreV1().ConfigMaps("default").Create(ctx, cm, v1.CreateOptions{})
//	        return err
//	    },
//	}
//
// ### Adding Negative Permission Tests
//
// To verify the webhook does NOT have a permission:
//
// 1. Add an entry to the mustNotHave slice in TestWebhookRBAC
// 2. Use the permissionTest struct with allowed=false
//
// Example:
//
//	{name: "delete configmaps", group: "", resource: "configmaps", verb: "delete", allowed: false}
//
package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	webhookServiceAccount = "rancher-webhook"
	webhookNamespace      = "cattle-system"
	webhookClusterRole    = "rancher-webhook"
)

// permissionTest represents a single permission check
type permissionTest struct {
	name      string
	group     string
	resource  string
	verb      string
	namespace string // empty for cluster-scoped
	allowed   bool   // true = must have, false = must not have
}

// TestWebhookRBAC validates that the webhook ServiceAccount has the exact permissions it needs.
// This test reads the deployed rancher-webhook ClusterRole and validates each rule via SubjectAccessReview.
func (m *IntegrationSuite) TestWebhookRBAC() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	k8sClient, err := kubernetes.NewForConfig(m.restCfg)
	require.NoError(m.T(), err, "Failed to create kubernetes client")

	m.T().Run("VerifyDeployedPermissions", func(t *testing.T) {
		// Fetch the actual ClusterRole deployed by the chart
		clusterRole, err := k8sClient.RbacV1().ClusterRoles().Get(ctx, webhookClusterRole, v1.GetOptions{})
		require.NoError(t, err, "Failed to fetch rancher-webhook ClusterRole")

		// Generate permission tests from ClusterRole rules
		tests := parseClusterRoleRules(clusterRole.Rules)
		require.NotEmpty(t, tests, "ClusterRole has no rules")

		// Test each permission
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				allowed := checkPermission(ctx, k8sClient, tc)
				assert.True(t, allowed, "Webhook should have permission: %s", tc.name)
			})
		}
	})

	m.T().Run("VerifyRegisteredWebhooksHaveRBAC", func(t *testing.T) {
		// This test catches missing RBAC when a new validator/mutator is added.
		// It reads the deployed WebhookConfigurations to find all resources the webhook handles,
		// then verifies the ClusterRole grants read permissions for those resources.

		clusterRole, err := k8sClient.RbacV1().ClusterRoles().Get(ctx, webhookClusterRole, v1.GetOptions{})
		require.NoError(t, err, "Failed to fetch rancher-webhook ClusterRole")

		// Get ValidatingWebhookConfiguration
		vwc, err := k8sClient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "rancher.cattle.io", v1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			t.Fatalf("Failed to fetch ValidatingWebhookConfiguration: %v", err)
		}

		// Get MutatingWebhookConfiguration
		mwc, err := k8sClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "rancher.cattle.io", v1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			t.Fatalf("Failed to fetch MutatingWebhookConfiguration: %v", err)
		}

		// Extract all resources handled by webhooks
		handledResources := make(map[string]bool)
		if vwc != nil {
			for _, wh := range vwc.Webhooks {
				for _, rule := range wh.Rules {
					for _, group := range rule.APIGroups {
						for _, resource := range rule.Resources {
							key := fmt.Sprintf("%s/%s", group, resource)
							handledResources[key] = true
						}
					}
				}
			}
		}
		if mwc != nil {
			for _, wh := range mwc.Webhooks {
				for _, rule := range wh.Rules {
					for _, group := range rule.APIGroups {
						for _, resource := range rule.Resources {
							key := fmt.Sprintf("%s/%s", group, resource)
							handledResources[key] = true
						}
					}
				}
			}
		}

		// Build a map of resources the ClusterRole can read
		grantedReadResources := make(map[string]bool)
		for _, rule := range clusterRole.Rules {
			hasRead := false
			for _, verb := range rule.Verbs {
				if verb == "get" || verb == "list" || verb == "watch" || verb == "*" {
					hasRead = true
					break
				}
			}
			if hasRead {
				for _, group := range rule.APIGroups {
					for _, resource := range rule.Resources {
						if resource == "*" {
							// Wildcard grants all resources in this group
							grantedReadResources[fmt.Sprintf("%s/*", group)] = true
						} else {
							grantedReadResources[fmt.Sprintf("%s/%s", group, resource)] = true
						}
					}
				}
			}
		}

		// Verify each handled resource has read permission
		for resourceKey := range handledResources {
			// Skip resources the webhook doesn't actually need to read
			// (e.g., namespaces CREATE webhook doesn't need to read namespaces)
			// This list should be kept minimal
			skipResources := map[string]bool{
				// Add exceptions here if needed, with comments explaining why
			}
			if skipResources[resourceKey] {
				continue
			}

			// Extract group from "group/resource" format
			parts := splitGroupResource(resourceKey)
			group := parts[0]

			// Check if granted (exact match or wildcard)
			granted := grantedReadResources[resourceKey] || grantedReadResources[fmt.Sprintf("%s/*", group)]

			assert.True(t, granted,
				"Webhook handles %s but ClusterRole lacks read permission. "+
				"Add the resource to charts/rancher-webhook/templates/rbac.yaml", resourceKey)
		}
	})

	m.T().Run("VerifyNoExcessPermissions", func(t *testing.T) {
		// Permissions webhook should NOT have (destructive operations, resource creation for Rancher CRDs)
		mustNotHave := []permissionTest{
			{name: "delete globalroles", group: "management.cattle.io", resource: "globalroles", verb: "delete", allowed: false},
			{name: "create globalroles", group: "management.cattle.io", resource: "globalroles", verb: "create", allowed: false},
			{name: "update globalroles", group: "management.cattle.io", resource: "globalroles", verb: "update", allowed: false},
			{name: "delete roletemplates", group: "management.cattle.io", resource: "roletemplates", verb: "delete", allowed: false},
			{name: "create roletemplates", group: "management.cattle.io", resource: "roletemplates", verb: "create", allowed: false},
			{name: "delete clusterroles", group: "rbac.authorization.k8s.io", resource: "clusterroles", verb: "delete", allowed: false},
			{name: "create clusterroles", group: "rbac.authorization.k8s.io", resource: "clusterroles", verb: "create", allowed: false},
			{name: "delete clusterrolebindings", group: "rbac.authorization.k8s.io", resource: "clusterrolebindings", verb: "delete", allowed: false},
			{name: "delete namespaces", group: "", resource: "namespaces", verb: "delete", allowed: false},
			{name: "delete pods", group: "", resource: "pods", verb: "delete", allowed: false},
		}

		for _, tc := range mustNotHave {
			t.Run(tc.name, func(t *testing.T) {
				allowed := checkPermission(ctx, k8sClient, tc)
				assert.False(t, allowed, "Webhook should NOT have permission: %s", tc.name)
			})
		}
	})
}

// operationTest defines a test that performs an actual operation as the webhook ServiceAccount
type operationTest struct {
	name      string
	shouldErr bool                                                    // true if operation should fail
	operation func(ctx context.Context, webhookClient, adminClient *kubernetes.Clientset) error
}

// TestWebhookRBACActual performs actual operations as the webhook ServiceAccount to validate RBAC.
// This test uses impersonation to verify the webhook can perform the operations it needs.
//
// To add a new operation test:
//  1. Add an entry to the operations slice
//  2. Define the operation function that performs the actual k8s API call
//  3. Set shouldErr=true if the webhook should NOT be able to perform this operation
func (m *IntegrationSuite) TestWebhookRBACActual() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	// Admin client for setup/cleanup
	adminClient, err := kubernetes.NewForConfig(m.restCfg)
	require.NoError(m.T(), err, "Failed to create admin client")

	// Impersonated client for webhook ServiceAccount
	impersonatedCfg := rest.CopyConfig(m.restCfg)
	impersonatedCfg.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + webhookNamespace + ":" + webhookServiceAccount,
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + webhookNamespace},
	}

	webhookClient, err := kubernetes.NewForConfig(impersonatedCfg)
	require.NoError(m.T(), err, "Failed to create impersonated client")

	// Define operations to test
	operations := []operationTest{
		{
			name:      "CreateNamespace",
			shouldErr: false,
			operation: func(ctx context.Context, webhookClient, _ *kubernetes.Clientset) error {
				ns := &corev1.Namespace{ObjectMeta: v1.ObjectMeta{GenerateName: "rbac-test-"}}
				created, err := webhookClient.CoreV1().Namespaces().Create(ctx, ns, v1.CreateOptions{})
				if err == nil {
					_ = webhookClient.CoreV1().Namespaces().Delete(ctx, created.Name, v1.DeleteOptions{})
				}
				return err
			},
		},
		{
			name:      "CreateRoleBinding",
			shouldErr: false,
			operation: func(ctx context.Context, webhookClient, _ *kubernetes.Clientset) error {
				rb := &rbacv1.RoleBinding{
					ObjectMeta: v1.ObjectMeta{Name: "rbac-test-rb", Namespace: m.testnamespace},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user", APIGroup: "rbac.authorization.k8s.io"}},
				}
				created, err := webhookClient.RbacV1().RoleBindings(m.testnamespace).Create(ctx, rb, v1.CreateOptions{})
				if err == nil {
					_ = webhookClient.RbacV1().RoleBindings(m.testnamespace).Delete(ctx, created.Name, v1.DeleteOptions{})
				}
				return err
			},
		},
		{
			name:      "CreateClusterRoleBinding",
			shouldErr: false,
			operation: func(ctx context.Context, webhookClient, _ *kubernetes.Clientset) error {
				crb := &rbacv1.ClusterRoleBinding{
					ObjectMeta: v1.ObjectMeta{GenerateName: "rbac-test-crb-"},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user", APIGroup: "rbac.authorization.k8s.io"}},
				}
				created, err := webhookClient.RbacV1().ClusterRoleBindings().Create(ctx, crb, v1.CreateOptions{})
				if err == nil {
					_ = webhookClient.RbacV1().ClusterRoleBindings().Delete(ctx, created.Name, v1.DeleteOptions{})
				}
				return err
			},
		},
		{
			name:      "CannotDeleteClusterRole",
			shouldErr: true,
			operation: func(ctx context.Context, webhookClient, adminClient *kubernetes.Clientset) error {
				cr := &rbacv1.ClusterRole{
					ObjectMeta: v1.ObjectMeta{GenerateName: "rbac-test-nodelete-"},
					Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
				}
				created, err := adminClient.RbacV1().ClusterRoles().Create(ctx, cr, v1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("admin failed to create ClusterRole: %w", err)
				}
				defer adminClient.RbacV1().ClusterRoles().Delete(ctx, created.Name, v1.DeleteOptions{})

				return webhookClient.RbacV1().ClusterRoles().Delete(ctx, created.Name, v1.DeleteOptions{})
			},
		},
	}

	// Run each operation test
	for _, op := range operations {
		m.T().Run(op.name, func(t *testing.T) {
			err := op.operation(ctx, webhookClient, adminClient)
			if op.shouldErr {
				assert.Error(t, err, "Operation should fail but succeeded")
				if err != nil && !apierrors.IsForbidden(err) {
					t.Logf("Expected Forbidden error, got: %v", err)
				}
			} else {
				assert.NoError(t, err, "Operation should succeed but failed")
			}
		})
	}
}
// parseClusterRoleRules converts RBAC PolicyRules into permissionTest cases
func parseClusterRoleRules(rules []rbacv1.PolicyRule) []permissionTest {
	var tests []permissionTest

	for _, rule := range rules {
		// Each rule can have multiple APIGroups, Resources, and Verbs
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				// Skip wildcard resources - can't test them specifically
				if resource == "*" {
					continue
				}

				for _, verb := range rule.Verbs {
					// Skip wildcard verbs
					if verb == "*" {
						continue
					}

					name := fmt.Sprintf("%s %s in %s", verb, resource, group)
					if group == "" {
						name = fmt.Sprintf("%s %s (core)", verb, resource)
					}

					tests = append(tests, permissionTest{
						name:     name,
						group:    group,
						resource: resource,
						verb:     verb,
						allowed:  true,
					})
				}
			}
		}
	}

	return tests
}

// checkPermission uses SubjectAccessReview to check if webhook SA has a specific permission
func checkPermission(ctx context.Context, k8sClient *kubernetes.Clientset, test permissionTest) bool {
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: test.namespace,
				Verb:      test.verb,
				Group:     test.group,
				Resource:  test.resource,
			},
			User:   "system:serviceaccount:" + webhookNamespace + ":" + webhookServiceAccount,
			Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + webhookNamespace},
		},
	}

	result, err := k8sClient.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, v1.CreateOptions{})
	if err != nil {
		return false
	}

	return result.Status.Allowed
}

// splitGroupResource splits "group/resource" into [group, resource]
// For core resources (e.g., "/namespaces"), returns ["", "namespaces"]
func splitGroupResource(key string) [2]string {
	parts := [2]string{"", ""}
	for i, part := range []rune(key) {
		if part == '/' {
			parts[0] = key[:i]
			parts[1] = key[i+1:]
			return parts
		}
	}
	// No slash found - shouldn't happen, but handle gracefully
	parts[1] = key
	return parts
}
