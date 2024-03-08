package clusterrepo

import (
	"context"
	"encoding/json"
	"testing"

	catalogv1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestClusterRepoValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		clusterRepo *catalogv1.ClusterRepo
		operation   admissionv1.Operation
		wantAllowed bool
	}{
		{
			name: "Both GitRepo and URL are set when creating",
			clusterRepo: &catalogv1.ClusterRepo{
				Spec: catalogv1.RepoSpec{
					URL:     "https://url.com",
					GitRepo: "https://github.com",
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: false,
		},
		{
			name: "Both GitRepo and URL are set when updating",
			clusterRepo: &catalogv1.ClusterRepo{
				Spec: catalogv1.RepoSpec{
					URL:     "https://url.com",
					GitRepo: "https://github.com",
				},
			},
			operation:   admissionv1.Update,
			wantAllowed: false,
		},
		{
			name: "Neither GitRepo and URL are set when creating",
			clusterRepo: &catalogv1.ClusterRepo{
				Spec: catalogv1.RepoSpec{},
			},
			operation:   admissionv1.Create,
			wantAllowed: false,
		},
		{
			name: "Neither GitRepo and URL are set when updating",
			clusterRepo: &catalogv1.ClusterRepo{
				Spec: catalogv1.RepoSpec{},
			},
			operation:   admissionv1.Update,
			wantAllowed: false,
		},
		{
			name: "Only GitRepo is set when creating",
			clusterRepo: &catalogv1.ClusterRepo{
				Spec: catalogv1.RepoSpec{
					GitRepo: "https://github.com",
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: true,
		},
		{
			name: "Only GitRepo is set when updating",
			clusterRepo: &catalogv1.ClusterRepo{
				Spec: catalogv1.RepoSpec{
					GitRepo: "https://github.com",
				},
			},
			operation:   admissionv1.Update,
			wantAllowed: true,
		},
		{
			name: "Only URL is set when creating",
			clusterRepo: &catalogv1.ClusterRepo{
				Spec: catalogv1.RepoSpec{
					URL: "https://url.com",
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: true,
		},
		{
			name: "Only URL is set when updating",
			clusterRepo: &catalogv1.ClusterRepo{
				Spec: catalogv1.RepoSpec{
					URL: "https://url.com",
				},
			},
			operation:   admissionv1.Update,
			wantAllowed: true,
		},
	}

	validator := NewValidator()
	admitters := validator.Admitters()

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			req, err := createClusterRepo(test.clusterRepo, test.operation, false)
			assert.NoError(t, err)
			assert.Len(t, admitters, 1)
			response, err := admitters[0].Admit(req)
			assert.NoError(t, err)
			assert.Equal(t, test.wantAllowed, response.Allowed)
		})
	}
}

func createClusterRepo(newClusterRepo *catalogv1.ClusterRepo, operation admissionv1.Operation, dryRun bool) (*admission.Request, error) {
	gvk := metav1.GroupVersionKind{Group: "catalog.cattle.io", Version: "v1", Kind: "ClusterRepo"}
	gvr := metav1.GroupVersionResource{Group: "catalog.cattle.io", Version: "v1", Resource: "clusterrepos"}
	req := &admission.Request{
		Context: context.Background(),
	}

	req.AdmissionRequest = admissionv1.AdmissionRequest{
		Kind:            gvk,
		Resource:        gvr,
		RequestKind:     &gvk,
		RequestResource: &gvr,
		Operation:       operation,
		Object:          runtime.RawExtension{},
		OldObject:       runtime.RawExtension{},
		DryRun:          &dryRun,
	}
	if newClusterRepo != nil {
		var err error
		req.Object.Raw, err = json.Marshal(newClusterRepo)
		if err != nil {
			return nil, err
		}
	}

	return req, nil
}
