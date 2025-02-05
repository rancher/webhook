package namespace

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGVR(t *testing.T) {
	validator := NewValidator(nil)
	gvr := validator.GVR()
	assert.Equal(t, "v1", gvr.Version)
	assert.Equal(t, "namespaces", gvr.Resource)
	assert.Equal(t, "", gvr.Group)
}

func TestOperations(t *testing.T) {
	validator := NewValidator(nil)
	operations := validator.Operations()
	assert.Len(t, operations, 3)
	assert.Contains(t, operations, v1.Update)
	assert.Contains(t, operations, v1.Create)
}

func TestAdmitters(t *testing.T) {
	validator := NewValidator(nil)
	admitters := validator.Admitters()
	assert.Len(t, admitters, 2)
	hasPSAAdmitter := false
	hasProjectNamespaceAdmitter := false
	for i := range admitters {
		admitter := admitters[i]
		_, ok := admitter.(*psaLabelAdmitter)
		if ok {
			hasPSAAdmitter = true
			continue
		}
		_, ok = admitter.(*projectNamespaceAdmitter)
		if ok {
			hasProjectNamespaceAdmitter = true
			continue
		}
	}
	assert.True(t, hasPSAAdmitter, "admitters did not contain a PSA admitter")
	assert.True(t, hasProjectNamespaceAdmitter, "admitters did not contain a projectNamespaceAdmitter")
}

func TestValidatingWebhook(t *testing.T) {
	testURL := "test.cattle.io"
	clientConfig := v1.WebhookClientConfig{
		URL: &testURL,
	}
	wantURL := "test.cattle.io/namespaces"
	validator := NewValidator(nil)
	webhooks := validator.ValidatingWebhook(clientConfig)
	assert.Len(t, webhooks, 4)
	hasAllUpdateWebhook := false
	hasCreateNonKubeSystemWebhook := false
	hasCreateKubeSystemWebhook := false
	for _, webhook := range webhooks {
		// all webhooks should resolve to the same endpoint, have only 1 rule/operation, and be for the cluster scope
		assert.Equal(t, wantURL, *webhook.ClientConfig.URL)
		rules := webhook.Rules
		assert.Len(t, rules, 1)
		rule := rules[0]
		operations := rule.Operations
		assert.Len(t, operations, 1)
		operation := operations[0]
		assert.Equal(t, v1.ClusterScope, *rule.Scope)

		assert.Contains(t, []v1.OperationType{v1.Create, v1.Update, v1.Delete}, operation, "only expected webhooks for create, update and delete")
		if operation == v1.Update {
			assert.False(t, hasAllUpdateWebhook, "had more than one webhook validating update calls, exepcted only one")
			hasAllUpdateWebhook = true
			assert.Nil(t, webhook.NamespaceSelector)
			assert.Nil(t, webhook.ObjectSelector)
			if webhook.FailurePolicy != nil {
				// failure policy defaults to fail, but if we specify one it needs to be fail
				assert.Equal(t, v1.Fail, *webhook.FailurePolicy)
			}
		} else if operation == v1.Create {
			assert.NotNil(t, webhook.NamespaceSelector)
			matchExpressions := webhook.NamespaceSelector.MatchExpressions
			assert.Len(t, matchExpressions, 1)
			matchExpression := matchExpressions[0]
			assert.Len(t, matchExpression.Values, 1)
			assert.Equal(t, "kube-system", matchExpression.Values[0])
			assert.Equal(t, corev1.LabelMetadataName, matchExpression.Key)
			assert.Contains(t, []metav1.LabelSelectorOperator{metav1.LabelSelectorOpIn, metav1.LabelSelectorOpNotIn}, matchExpression.Operator)
			if matchExpression.Operator == metav1.LabelSelectorOpIn {
				assert.False(t, hasCreateKubeSystemWebhook, "had more than one webhook for creation on kube-system")
				hasCreateKubeSystemWebhook = true
				assert.NotNil(t, webhook.FailurePolicy)
				assert.Equal(t, v1.Ignore, *webhook.FailurePolicy)
			} else {
				assert.False(t, hasCreateNonKubeSystemWebhook, "had more than one webhook for creation on kube-system")
				hasCreateNonKubeSystemWebhook = true
				if webhook.FailurePolicy != nil {
					assert.Equal(t, v1.Fail, *webhook.FailurePolicy)
				}
			}
		}
	}

	assert.True(t, hasAllUpdateWebhook, "was missing expected webhook which validates all namespace on update")
	assert.True(t, hasCreateKubeSystemWebhook, "was missing expected webhook create on kube system namespace")
	assert.True(t, hasCreateNonKubeSystemWebhook, "was missing expected webhook create on non-kube-system namespaces")
}
