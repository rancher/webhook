package feature

import (
	"fmt"
	"net/http"
	"time"

	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"
)

func NewValidator() webhook.Handler {
	return &featureValidator{}
}

type featureValidator struct{}

func (fv *featureValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("featureValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	oldFeature, newFeature, err := objectsv3.FeatureOldAndNewFromRequest(request)
	if err != nil {
		return err
	}

	if !isValidFeatureValue(newFeature.Status.LockedValue, oldFeature.Spec.Value, newFeature.Spec.Value) {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: fmt.Sprintf("feature flag cannot be changed from current value: %v", *newFeature.Status.LockedValue),
			Reason:  metav1.StatusReasonInvalid,
			Code:    http.StatusBadRequest,
		}
		response.Allowed = false
		return nil
	}

	response.Allowed = true
	return nil
}

// isValidFeatureValue checks that desired value does not change value on spec unless lockedValue
// is nil or it is equal to the lockedValue.
func isValidFeatureValue(lockedValue *bool, oldSpecValue *bool, desiredSpecValue *bool) bool {
	if lockedValue == nil {
		return true
	}

	if oldSpecValue == nil && desiredSpecValue == nil {
		return true
	}

	if oldSpecValue != nil && desiredSpecValue != nil && *oldSpecValue == *desiredSpecValue {
		return true
	}

	if desiredSpecValue != nil && *desiredSpecValue == *lockedValue {
		return true
	}

	return false
}
