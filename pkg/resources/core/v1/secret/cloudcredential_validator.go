package secret

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	ctrlv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	ctrlprovv1 "github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io/v1"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"
)

const (
	// CredentialNamespace is the namespace where CloudCredential secrets are stored.
	CredentialNamespace = "cattle-cloud-credentials"

	// TypePrefix is the prefix for the Secret type field to identify cloud credential secrets.
	TypePrefix = "rke.cattle.io/cloud-credential-"

	// CredentialConfigSuffix is appended to the type to form the credential config schema name.
	// Must be lowercase to match how DynamicSchemas are registered by node drivers and KEv2 operators.
	CredentialConfigSuffix = "credentialconfig"

	// Indexer names for looking up provisioning clusters by cloud credential reference.
	byCloudCred            = "by-cloud-cred"
	byMachinePoolCloudCred = "by-machine-pool-cloud-cred"
	byEtcdS3CloudCred      = "by-etcd-s3-cloud-cred"
)

type cloudCredentialAdmitter struct {
	dynamicSchemaCache ctrlv3.DynamicSchemaCache
	featureCache       ctrlv3.FeatureCache
	provClusterCache   ctrlprovv1.ClusterCache
}

// AdmitCloudCredential handles the webhook admission request for cloud credential secrets.
func (a *cloudCredentialAdmitter) AdmitCloudCredential(secret *corev1.Secret, request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("cloudCredential Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	// DELETE operations: check if the credential is in use (unless force-delete)
	if request.Operation == admissionv1.Delete {
		return a.admitDelete(request)
	}

	// Extract credential type from secret type (e.g., "rke.cattle.io/cloud-credential-amazonec2" -> "amazonec2")
	credType := strings.TrimPrefix(string(secret.Type), TypePrefix)
	if credType == "" {
		return admission.ResponseBadRequest("cloud credential secret type is missing the provider type suffix"), nil
	}

	// Look up the dynamic schema for this credential type
	schemaName := credType + CredentialConfigSuffix
	dynamicSchema, err := a.dynamicSchemaCache.Get(schemaName)
	if err != nil {
		// if it isn't found - see if generic credentials are enabled
		if apierrors.IsNotFound(err) {
			if err := a.validateGenericCredentialType(credType); err != nil {
				return admission.ResponseBadRequest(err.Error()), nil
			}
			return admission.ResponseAllowed(), nil
		}

		return nil, fmt.Errorf("failed to get dynamic schema %s: %w", schemaName, err)
	}

	// Validate the secret data against the schema
	if err := validateSecretAgainstSchema(secret.Data, dynamicSchema); err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	return admission.ResponseAllowed(), nil
}

func (a *cloudCredentialAdmitter) validateGenericCredentialType(credType string) error {
	genericCloudCredentials, err := a.featureCache.Get(common.GenericCloudCredentialsFeatureName)
	if err != nil {
		return fmt.Errorf("failed to determine status of '%s' feature", common.GenericCloudCredentialsFeatureName)
	}

	enabled := genericCloudCredentials.Status.Default
	if genericCloudCredentials.Spec.Value != nil {
		enabled = *genericCloudCredentials.Spec.Value
	}

	if !enabled {
		return fmt.Errorf(
			"credential type %q has no corresponding DynamicSchema and the %q feature is not enabled",
			credType,
			common.GenericCloudCredentialsFeatureName,
		)
	}

	if credType != "generic" && !strings.HasPrefix(credType, "x-") {
		return fmt.Errorf(
			"credential type %q has no corresponding DynamicSchema; only %q-prefixed generic types are allowed when %q is enabled",
			credType,
			"x-",
			common.GenericCloudCredentialsFeatureName,
		)
	}

	return nil
}

// validateSecretAgainstSchema validates the secret data fields against the dynamic schema.
// It checks that all required fields are present and validates field constraints.
func validateSecretAgainstSchema(data map[string][]byte, schema *v3.DynamicSchema) error {
	// Check required fields
	for fieldName, field := range schema.Spec.ResourceFields {
		if !field.Required {
			continue
		}

		value, exists := data[fieldName]
		if !exists || len(value) == 0 {
			return fmt.Errorf("required field %q is missing", fieldName)
		}
	}

	// Validate field constraints for fields that exist in the secret
	for dataKey, value := range data {
		field, exists := schema.Spec.ResourceFields[dataKey]
		if !exists {
			// Field not in schema - allow it (don't be overly strict)
			continue
		}

		// Validate string length constraints
		strValue := string(value)
		if field.MinLength > 0 && int64(len(strValue)) < field.MinLength {
			return fmt.Errorf("field %q must be at least %d characters", dataKey, field.MinLength)
		}
		if field.MaxLength > 0 && int64(len(strValue)) > field.MaxLength {
			return fmt.Errorf("field %q must be at most %d characters", dataKey, field.MaxLength)
		}

		// Validate options (enum values)
		if len(field.Options) > 0 {
			valid := false
			for _, opt := range field.Options {
				if strValue == opt {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("field %q must be one of: %s", dataKey, strings.Join(field.Options, ", "))
			}
		}
	}

	return nil
}

// admitDelete handles DELETE admission requests by checking if the cloud credential
// is still referenced by provisioning clusters or machine pools.
// Force-delete (GracePeriodSeconds=0) bypasses the in-use check.
func (a *cloudCredentialAdmitter) admitDelete(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	secret, err := objectsv1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret from request: %w", err)
	}

	// Check for force-delete via GracePeriodSeconds=0 in DeleteOptions
	if request.Options.Raw != nil {
		var deleteOpts metav1.DeleteOptions
		if err := json.Unmarshal(request.Options.Raw, &deleteOpts); err == nil {
			if deleteOpts.GracePeriodSeconds != nil && *deleteOpts.GracePeriodSeconds == 0 {
				return admission.ResponseAllowed(), nil
			}
		}
	}

	if resp, err := a.checkInUse(secret.Name); err != nil || !resp.Allowed {
		return resp, err
	}

	return admission.ResponseAllowed(), nil
}

// checkInUse checks if the credential's backing secret is referenced by any provisioning
// clusters (at the cluster level or within machine pools).
func (a *cloudCredentialAdmitter) checkInUse(secretName string) (*admissionv1.AdmissionResponse, error) {
	// Check provisioning clusters at cluster level
	clusters, err := a.provClusterCache.GetByIndex(byCloudCred, secretName)
	if err != nil {
		return nil, fmt.Errorf("error checking cloud credential references: %w", err)
	}
	if len(clusters) > 0 {
		return admission.ResponseBadRequest(
			fmt.Sprintf("cloud credential is currently referenced by provisioning cluster %s/%s",
				clusters[0].Namespace, clusters[0].Name),
		), nil
	}

	// Check machine pools within provisioning clusters
	clusters, err = a.provClusterCache.GetByIndex(byMachinePoolCloudCred, secretName)
	if err != nil {
		return nil, fmt.Errorf("error checking cloud credential machine pool references: %w", err)
	}
	if len(clusters) > 0 {
		return admission.ResponseBadRequest(
			fmt.Sprintf("cloud credential is currently referenced by a machine pool in provisioning cluster %s/%s",
				clusters[0].Namespace, clusters[0].Name),
		), nil
	}

	// Check ETCD S3 cloud credential references within provisioning clusters
	clusters, err = a.provClusterCache.GetByIndex(byEtcdS3CloudCred, secretName)
	if err != nil {
		return nil, fmt.Errorf("error checking cloud credential etcd s3 references: %w", err)
	}
	if len(clusters) > 0 {
		return admission.ResponseBadRequest(
			fmt.Sprintf("cloud credential is currently referenced by etcd s3 config in provisioning cluster %s/%s",
				clusters[0].Namespace, clusters[0].Name),
		), nil
	}

	return admission.ResponseAllowed(), nil
}

// byCloudCredentialIndex returns the cluster-level cloud credential reference.
func byCloudCredentialIndex(obj *provv1.Cluster) ([]string, error) {
	secretName, ok := normalizeCloudCredentialSecretRef(obj.Spec.CloudCredentialSecretName)
	if !ok {
		return nil, nil
	}

	return []string{secretName}, nil
}

// byEtcdS3CloudCredIndex returns the ETCD S3 cloud credential reference.
func byEtcdS3CloudCredIndex(obj *provv1.Cluster) ([]string, error) {
	if obj.Spec.RKEConfig == nil || obj.Spec.RKEConfig.ClusterConfiguration.ETCD == nil || obj.Spec.RKEConfig.ClusterConfiguration.ETCD.S3 == nil {
		return nil, nil
	}

	secretName, ok := normalizeCloudCredentialSecretRef(obj.Spec.RKEConfig.ClusterConfiguration.ETCD.S3.CloudCredentialName)
	if !ok {
		return nil, nil
	}

	return []string{secretName}, nil
}

// byMachinePoolCloudCredIndex returns all cloud credential references from machine pools.
func byMachinePoolCloudCredIndex(obj *provv1.Cluster) ([]string, error) {
	credentialsSet := make(map[string]struct{})

	if obj.Spec.RKEConfig != nil {
		for _, machinePool := range obj.Spec.RKEConfig.MachinePools {
			secretName, ok := normalizeCloudCredentialSecretRef(machinePool.CloudCredentialSecretName)
			if !ok {
				continue
			}
			credentialsSet[secretName] = struct{}{}
		}
	}

	if len(credentialsSet) == 0 {
		return nil, nil
	}

	credentialSlice := make([]string, 0, len(credentialsSet))
	for cred := range credentialsSet {
		credentialSlice = append(credentialSlice, cred)
	}

	sort.Strings(credentialSlice)

	return credentialSlice, nil
}

// normalizeCloudCredentialSecretRef canonicalizes cloud credential refs to backing secret name.
// Accepted formats are "name" and "namespace:name".
func normalizeCloudCredentialSecretRef(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false
	}

	if _, name, found := strings.Cut(ref, ":"); found {
		if name == "" {
			return "", false
		}
		return name, true
	}

	return ref, true
}
