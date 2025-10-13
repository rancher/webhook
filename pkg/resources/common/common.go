package common

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	// CreatorIDAnn is an annotation key for the id of the creator.
	CreatorIDAnn = "field.cattle.io/creatorId"
	// CreatorPrincipalNameAnn is an annotation key for the principal name of the creator.
	CreatorPrincipalNameAnn = "field.cattle.io/creator-principal-name"
	// NoCreatorRBACAnn is an annotation key to indicate that a cluster doesn't need
	NoCreatorRBACAnn = "field.cattle.io/no-creator-rbac"
	// SchedulingCustomizationFeatureName is the feature name for enabling customization of PDBs and PCs for the
	// cattle-cluster-agent
	SchedulingCustomizationFeatureName = "cluster-agent-scheduling-customization"
)

// PdbPercentageRegex ensures that a given string is a properly formatted percentage value
// between 0% and 100% so that it can be used in a Pod Disruption Budget
var PdbPercentageRegex = regexp.MustCompile("^([0-9]|[1-9][0-9]|100)%$")

// ConvertAuthnExtras converts authnv1 type extras to authzv1 extras. Technically these are both
// type alias to string, so the conversion is straightforward
func ConvertAuthnExtras(extra map[string]authnv1.ExtraValue) map[string]authzv1.ExtraValue {
	result := map[string]authzv1.ExtraValue{}
	for k, v := range extra {
		result[k] = authzv1.ExtraValue(v)
	}
	return result
}

// ValidateLabel checks if a user is removing or modifying a label. If the label is newly added, return false.
func IsModifyingLabel(oldLabels, newLabels map[string]string, label string) bool {
	var oldValue, newValue string
	var oldLabelExists, newLabelExists bool
	if oldLabels == nil {
		oldLabelExists = false
	} else {
		oldValue, oldLabelExists = oldLabels[label]
	}
	if newLabels == nil {
		newLabelExists = false
	} else {
		newValue, newLabelExists = newLabels[label]
	}

	if !oldLabelExists {
		return false
	}
	if oldLabelExists && !newLabelExists {
		return true
	}
	if oldValue != newValue {
		return true
	}

	return false
}

// CachedVerbChecker is used for caching if a request for a non-namespaced gvr with specified name has the given overrideVerb.
// This is meant to eliminate the need to perform multiple calls to the provided SubjectAccessReview for the overrideVerb.
// Each CachedVerbChecker is unique to the initial set up. If the caller needs to change what it is checking
// (different verb, resource name, resource type) a new CachedVerbChecker must be created.
// A CachedVerbChecker should not be shared between admitters. Each admitter must request a new CachedVerbChecker.
// Additionally, the CachedVerbChecker should not be shared between requests, even for the same admitter.
type CachedVerbChecker struct {
	request            *admission.Request
	name               string
	sar                authorizationv1.SubjectAccessReviewInterface
	gvr                schema.GroupVersionResource
	overrideVerb       string
	hasVerbBeenChecked bool
	hasVerb            bool
}

// NewCachedVerbChecker creates a new CachedVerbChecker
func NewCachedVerbChecker(req *admission.Request, name string, sar authorizationv1.SubjectAccessReviewInterface, gvr schema.GroupVersionResource, verb string) *CachedVerbChecker {
	return &CachedVerbChecker{
		request:            req,
		name:               name,
		sar:                sar,
		gvr:                gvr,
		overrideVerb:       verb,
		hasVerbBeenChecked: false,
		hasVerb:            false,
	}
}

// IsRulesAllowed checks if the request has permissions to create the rules provided. Returns nil if the rules are allowed.
func (c *CachedVerbChecker) IsRulesAllowed(rules []v1.PolicyRule, resolver validation.AuthorizationRuleResolver, namespace string) error {
	err := auth.ConfirmNoEscalation(c.request, rules, namespace, resolver)
	// Check for the overrideVerb
	if err != nil {
		if c.HasVerb() {
			return nil
		}
	}
	return err
}

// HasVerb returns if the request has the overrideVerb. Only checks the request the first time called, after that it returns the cached value.
func (c *CachedVerbChecker) HasVerb() bool {
	var err error
	if c.hasVerbBeenChecked {
		return c.hasVerb
	}
	c.hasVerb, err = auth.RequestUserHasVerb(c.request, c.gvr, c.sar, c.overrideVerb, c.name, "")
	if err != nil {
		logrus.Errorf("Failed to check for the verb %s on %s: %v", c.overrideVerb, c.gvr.Resource, err)
		return false
	}
	c.hasVerbBeenChecked = true
	return c.hasVerb
}

// OldAndNewFromRequest gets the old and new objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for the object.
// Similarly, if the request is a Create operation, then the old object is the zero value for object.
func OldAndNewFromRequest[T any](request *admissionv1.AdmissionRequest) (*T, *T, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	var object T
	var oldObject T

	if request.Operation != admissionv1.Delete {
		err := json.Unmarshal(request.Object.Raw, &object)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal request object: %w", err)
		}
	}

	if request.Operation == admissionv1.Create {
		return &oldObject, &object, nil
	}

	err := json.Unmarshal(request.OldObject.Raw, &oldObject)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal request oldObject: %w", err)
	}

	return &oldObject, &object, nil
}
