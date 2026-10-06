package secret

import (
	"fmt"

	"github.com/rancher/rancher/pkg/plan"
	planv1alpha1 "github.com/rancher/rancher/pkg/plan/api/plan.cattle.io/v1alpha1"
	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/utils/trace"
)

const (
	machinePlanSecretType = "rke.cattle.io/machine-plan"

	// rkeClusterNameLabel is the label plan.NewCollector selects a cluster's machine-plan secrets by.
	rkeClusterNameLabel = "rke.cattle.io/cluster-name"
)

// immutablePlanLabels tie a machine-plan secret to its cluster and to its machine. Once set, none of
// them can be changed or removed. The machine-plan fence resolves a plan's beacon through the cluster
// labels, so changing them would let a writer point a plan at a beacon it holds, and changing the
// machine labels would detach a plan from its machine. None of the writers legitimately change them
// once set; the bootstrap and unmanaged controllers add them, which is allowed.
var immutablePlanLabels = []string{
	planv1alpha1.ClusterLifecycleGroupLabel,
	planv1alpha1.ClusterLifecycleKindLabel,
	planv1alpha1.ClusterLifecycleNameLabel,
	planv1alpha1.MachineLifecycleGroupLabel,
	planv1alpha1.MachineLifecycleKindLabel,
	planv1alpha1.MachineLifecycleNameLabel,
	rkeClusterNameLabel,
}

type planAdmitter struct {
	beacons beaconReader
}

// Admit validates machine-plan Secrets at admission time: data.plan, when present, must parse as a plan;
// on update the labels tying the secret to its cluster and machine can't be changed or removed once set;
// and on create and update a write that assigns, retries, cancels or pauses the plan must come from
// whoever holds the cluster's beacon (see checkWriter). Deletes are part of node removal, not plan
// assignment, and aren't checked.
func (p *planAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("secret planAdmitter Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	secret, err := objectsv1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret from request: %w", err)
	}

	if secret.Type != machinePlanSecretType {
		return admission.ResponseAllowed(), nil
	}

	if planData, ok := secret.Data["plan"]; ok {
		if _, err := plan.Parse(planData); err != nil {
			return admission.ResponseBadRequest(fmt.Sprintf("invalid plan: %v", err)), nil
		}
	}

	if request.Operation != admissionv1.Create && request.Operation != admissionv1.Update {
		return admission.ResponseAllowed(), nil
	}

	old, _, err := objectsv1.SecretOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret from request: %w", err)
	}

	if request.Operation == admissionv1.Update {
		if problem := changedPlanLabel(old.Labels, secret.Labels); problem != "" {
			return admission.ResponseBadRequest(fmt.Sprintf("machine-plan secret %s/%s: %s", secret.Namespace, secret.Name, problem)), nil
		}
	}

	if response, err := p.checkWriter(request.Context, old, secret, request.Operation == admissionv1.Create); response != nil || err != nil {
		return response, err
	}

	return admission.ResponseAllowed(), nil
}

// changedPlanLabel describes the first of immutablePlanLabels that was set on old and has been changed
// or removed in updated, or returns "" if none has. Each label is compared with the same key on both:
// a label absent on old may be added.
func changedPlanLabel(old, updated map[string]string) string {
	for _, key := range immutablePlanLabels {
		was, set := old[key]
		if !set {
			continue
		}
		now, kept := updated[key]
		if !kept {
			return fmt.Sprintf("label %s cannot be removed once set (was %q)", key, was)
		}
		if now != was {
			return fmt.Sprintf("label %s cannot be changed once set (from %q to %q)", key, was, now)
		}
	}
	return ""
}
