/*
Copyright 2023 Rancher Labs, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by codegen. DO NOT EDIT.

package v3

import (
	"github.com/rancher/lasso/pkg/controller"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/rancher/wrangler/pkg/schemes"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func init() {
	schemes.Register(v3.AddToScheme)
}

type Interface interface {
	Cluster() ClusterController
	ClusterRoleTemplateBinding() ClusterRoleTemplateBindingController
	GlobalRole() GlobalRoleController
	Node() NodeController
	PodSecurityAdmissionConfigurationTemplate() PodSecurityAdmissionConfigurationTemplateController
	ProjectRoleTemplateBinding() ProjectRoleTemplateBindingController
	RoleTemplate() RoleTemplateController
}

func New(controllerFactory controller.SharedControllerFactory) Interface {
	return &version{
		controllerFactory: controllerFactory,
	}
}

type version struct {
	controllerFactory controller.SharedControllerFactory
}

func (v *version) Cluster() ClusterController {
	return generic.NewNonNamespacedController[*v3.Cluster, *v3.ClusterList](schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Cluster"}, "clusters", v.controllerFactory)
}

func (v *version) ClusterRoleTemplateBinding() ClusterRoleTemplateBindingController {
	return generic.NewController[*v3.ClusterRoleTemplateBinding, *v3.ClusterRoleTemplateBindingList](schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "ClusterRoleTemplateBinding"}, "clusterroletemplatebindings", true, v.controllerFactory)
}

func (v *version) GlobalRole() GlobalRoleController {
	return generic.NewNonNamespacedController[*v3.GlobalRole, *v3.GlobalRoleList](schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRole"}, "globalroles", v.controllerFactory)
}

func (v *version) Node() NodeController {
	return generic.NewController[*v3.Node, *v3.NodeList](schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Node"}, "nodes", true, v.controllerFactory)
}

func (v *version) PodSecurityAdmissionConfigurationTemplate() PodSecurityAdmissionConfigurationTemplateController {
	return generic.NewNonNamespacedController[*v3.PodSecurityAdmissionConfigurationTemplate, *v3.PodSecurityAdmissionConfigurationTemplateList](schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "PodSecurityAdmissionConfigurationTemplate"}, "podsecurityadmissionconfigurationtemplates", v.controllerFactory)
}

func (v *version) ProjectRoleTemplateBinding() ProjectRoleTemplateBindingController {
	return generic.NewController[*v3.ProjectRoleTemplateBinding, *v3.ProjectRoleTemplateBindingList](schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "ProjectRoleTemplateBinding"}, "projectroletemplatebindings", true, v.controllerFactory)
}

func (v *version) RoleTemplate() RoleTemplateController {
	return generic.NewNonNamespacedController[*v3.RoleTemplate, *v3.RoleTemplateList](schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "RoleTemplate"}, "roletemplates", v.controllerFactory)
}
