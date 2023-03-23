package server

import v1 "k8s.io/api/admissionregistration/v1"

var rancherRules = []v1.RuleWithOperations{
	{
		Operations: []v1.OperationType{
			v1.Create,
			v1.Update,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"management.cattle.io"},
			APIVersions: []string{"v3"},
			Resources:   []string{"clusters"},
			Scope:       &clusterScope,
		},
	},
	{
		Operations: []v1.OperationType{
			v1.Update,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"management.cattle.io"},
			APIVersions: []string{"v3"},
			Resources:   []string{"features"},
			Scope:       &clusterScope,
		},
	},
}

var rancherAuthBaseRules = []v1.RuleWithOperations{
	{
		Operations: []v1.OperationType{
			v1.Create,
			v1.Update,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"provisioning.cattle.io"},
			APIVersions: []string{"v1"},
			Resources:   []string{"clusters"},
			Scope:       &namespaceScope,
		},
	},
	{
		Operations: []v1.OperationType{
			v1.Create,
			v1.Update,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"rke-machine-config.cattle.io"},
			APIVersions: []string{"v1"},
			Resources:   []string{"*"},
			Scope:       &namespaceScope,
		},
	},
}

var rancherAuthMCMRules = []v1.RuleWithOperations{
	{
		Operations: []v1.OperationType{
			v1.Create,
			v1.Update,
			v1.Delete,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"management.cattle.io"},
			APIVersions: []string{"v3"},
			Resources:   []string{"globalrolebindings"},
			Scope:       &clusterScope,
		},
	},
	{
		Operations: []v1.OperationType{
			v1.Create,
			v1.Update,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"management.cattle.io"},
			APIVersions: []string{"v3"},
			Resources:   []string{"roletemplates"},
			Scope:       &clusterScope,
		},
	},
	{
		Operations: []v1.OperationType{
			v1.Create,
			v1.Update,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"management.cattle.io"},
			APIVersions: []string{"v3"},
			Resources:   []string{"projectroletemplatebindings"},
			Scope:       &namespaceScope,
		},
	},
	{
		Operations: []v1.OperationType{
			v1.Create,
			v1.Update,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"management.cattle.io"},
			APIVersions: []string{"v3"},
			Resources:   []string{"clusterroletemplatebindings"},
			Scope:       &namespaceScope,
		},
	},
	{
		Operations: []v1.OperationType{
			v1.Create,
			v1.Update,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"management.cattle.io"},
			APIVersions: []string{"v3"},
			Resources:   []string{"globalroles"},
			Scope:       &clusterScope,
		},
	},
	{
		Operations: []v1.OperationType{
			v1.Delete,
		},
		Rule: v1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"secrets"},
			Scope:       &namespaceScope,
		},
	},
}

var fleetMutationRules = []v1.RuleWithOperations{
	{
		Operations: []v1.OperationType{
			v1.Create,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"management.cattle.io"},
			APIVersions: []string{"v3"},
			Resources:   []string{"fleetworkspaces"},
			Scope:       &clusterScope,
		},
	},
}

var rancherMutationRules = []v1.RuleWithOperations{
	{
		Operations: []v1.OperationType{
			v1.Create,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"provisioning.cattle.io"},
			APIVersions: []string{"v1"},
			Resources:   []string{"clusters"},
			Scope:       &namespaceScope,
		},
	},
	{
		Operations: []v1.OperationType{
			v1.Create,
		},
		Rule: v1.Rule{
			APIGroups:   []string{"rke-machine-config.cattle.io"},
			APIVersions: []string{"v1"},
			Resources:   []string{"*"},
			Scope:       &namespaceScope,
		},
	},
	{
		Operations: []v1.OperationType{
			v1.Create,
		},
		Rule: v1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"secrets"},
			Scope:       &namespaceScope,
		},
	},
}
