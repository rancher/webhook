//go:build ignore

package fakes

//go:generate mockgen --build_flags=--mod=mod -package fakes -destination ./clusterRoleCache.go github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1 ClusterRoleCache
//go:generate mockgen --build_flags=--mod=mod -package fakes -destination ./clusterRoleTemplateBinding.go github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3 ClusterRoleTemplateBindingController,ClusterRoleTemplateBindingClient,ClusterRoleTemplateBindingCache
//go:generate mockgen --build_flags=--mod=mod -package fakes -destination ./projectRoleTemplateBinding.go github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3 ProjectRoleTemplateBindingController,ProjectRoleTemplateBindingClient,ProjectRoleTemplateBindingCache
//go:generate mockgen --build_flags=--mod=mod -package fakes -destination ./globalRole.go github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3 GlobalRoleController,GlobalRoleClient,GlobalRoleCache
//go:generate mockgen --build_flags=--mod=mod -package fakes -destination ./roleTemplate.go github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3 RoleTemplateController,RoleTemplateClient,RoleTemplateCache
//go:generate mockgen --build_flags=--mod=mod -package fakes -destination ./k8Validation.go "k8s.io/kubernetes/pkg/registry/rbac/validation" AuthorizationRuleResolver
//go:generate mockgen --build_flags=--mod=mod -package fakes -destination ./RoleCache.go github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1 RoleCache,RoleController
//go:generate mockgen --build_flags=--mod=mod -package fakes -destination ./RoleBindingCache.go github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1 RoleBindingCache,RoleBindingController
//go:generate mockgen --build_flags=--mod=mod -package fakes -destination ./NodeDriverCache.go github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3 NodeCache
