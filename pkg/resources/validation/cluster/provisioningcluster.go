package cluster

import (
	"net/http"
	"regexp"
	"time"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/clients"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/resources/validation"
	"github.com/rancher/wrangler/pkg/kv"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

const globalNamespace = "cattle-global-data"

var mgmtNameRegex = regexp.MustCompile("^c-[a-z0-9]{5}$")

func NewProvisioningClusterValidator(client *clients.Clients) webhook.Handler {
	return &provisioningClusterValidator{
		sar:               client.K8s.AuthorizationV1().SubjectAccessReviews(),
		mgmtClusterClient: client.Management.Cluster(),
	}
}

type provisioningClusterValidator struct {
	sar               authorizationv1.SubjectAccessReviewInterface
	mgmtClusterClient v3.ClusterClient
}

func (p *provisioningClusterValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("provisioningClusterValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)
	oldCluster, cluster, err := objectsv1.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return err
	}

	if err := p.validateClusterName(request, response, cluster); err != nil || response.Result != nil {
		return err
	}

	if response.Result = validation.CheckCreatorID(request, oldCluster, cluster); response.Result != nil {
		return nil
	}

	if response.Result = validateACEConfig(cluster); response.Result != nil {
		return nil
	}

	if err := p.validateCloudCredentialAccess(request, response, oldCluster, cluster); err != nil || response.Result != nil {
		return err
	}

	response.Allowed = true
	return nil
}

func (p *provisioningClusterValidator) validateCloudCredentialAccess(request *webhook.Request, response *webhook.Response, oldCluster, newCluster *v1.Cluster) error {
	if newCluster.Spec.CloudCredentialSecretName == "" ||
		oldCluster.Spec.CloudCredentialSecretName == newCluster.Spec.CloudCredentialSecretName {
		return nil
	}

	secretNamespace, secretName := getCloudCredentialSecretInfo(newCluster.Namespace, newCluster.Spec.CloudCredentialSecretName)

	resp, err := p.sar.Create(request.Context, &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Verb:      "get",
				Version:   "v1",
				Resource:  "secrets",
				Group:     "",
				Name:      secretName,
				Namespace: secretNamespace,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			Extra:  toExtra(request.UserInfo.Extra),
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if resp.Status.Allowed {
		return nil
	}

	response.Result = &metav1.Status{
		Status:  "Failure",
		Message: resp.Status.Reason,
		Reason:  metav1.StatusReasonUnauthorized,
		Code:    http.StatusUnauthorized,
	}
	return nil
}

// getCloudCredentialSecretInfo returns the namespace and name of the secret based off the old cloud cred or new style
// cloud cred
func getCloudCredentialSecretInfo(namespace, name string) (string, string) {
	globalNS, globalName := kv.Split(name, ":")
	if globalName != "" && globalNS == globalNamespace {
		return globalNS, globalName
	}
	return namespace, name
}

func (p *provisioningClusterValidator) validateClusterName(request *webhook.Request, response *webhook.Response, cluster *v1.Cluster) error {
	if request.Operation != admissionv1.Create {
		return nil
	}

	// Look for an existing management cluster with the same name. If a management cluster with the given name does not
	// exists, then it should be checked that the provisioning cluster the user is trying to create is not of the form
	// "c-xxxxx" because names of that form are reserved for "legacy" management clusters.
	_, err := p.mgmtClusterClient.Get(cluster.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if !isValidName(cluster.Name, cluster.Namespace, err == nil) {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: "cluster name must be 63 characters or fewer, cannot be \"local\" nor of the form \"c-xxxxx\"",
			Reason:  metav1.StatusReasonInvalid,
			Code:    http.StatusUnprocessableEntity,
		}
	}

	return nil
}

func validateACEConfig(cluster *v1.Cluster) *metav1.Status {
	if cluster.Spec.RKEConfig != nil && cluster.Spec.LocalClusterAuthEndpoint.Enabled && cluster.Spec.LocalClusterAuthEndpoint.CACerts != "" && cluster.Spec.LocalClusterAuthEndpoint.FQDN == "" {
		return &metav1.Status{
			Status:  "Failure",
			Message: "CACerts defined but FQDN is not defined",
			Reason:  metav1.StatusReasonInvalid,
			Code:    http.StatusUnprocessableEntity,
		}
	}

	return nil
}

func isValidName(clusterName, clusterNamespace string, clusterExists bool) bool {
	// A provisioning cluster with name "local" is only expected to be created in the "fleet-local" namespace.
	if clusterName == "local" {
		return clusterNamespace == "fleet-local"
	}

	if mgmtNameRegex.MatchString(clusterName) {
		// A provisioning cluster with name of the form "c-xxxxx" is expected to be created if a management cluster
		// of the same name already exists because Rancher will create such a provisioning cluster.
		// Therefore, a cluster with name of the form "c-xxxxx" is only valid if it was found.
		return clusterExists
	}

	// Even though the name of the provisioning cluster object can be 253 characters, the name of the cluster is put in
	// various labels, by Rancher controllers and CAPI controllers. Because of this, the name of the cluster object should
	// be limited to 63 characters instead.
	return len(clusterName) <= 63
}
