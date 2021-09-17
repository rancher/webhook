package cluster

import (
	"testing"
)

func Test_isValidName(t *testing.T) {
	tests := []struct {
		name, clusterName, clusterNamespace string
		clusterExists                       bool
		want                                bool
	}{
		{
			name:             "local cluster in fleet-local",
			clusterName:      "local",
			clusterNamespace: "fleet-local",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "local cluster in fleet-local, cluster does not exist",
			clusterName:      "local",
			clusterNamespace: "fleet-local",
			clusterExists:    false,
			want:             true,
		},
		{
			name:             "local cluster not in fleet-local",
			clusterName:      "local",
			clusterNamespace: "fleet-default",
			clusterExists:    true,
			want:             false,
		},
		{
			name:             "c-xxxxx cluster exists",
			clusterName:      "c-12345",
			clusterNamespace: "default",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "c-xxxxx cluster does not exist",
			clusterName:      "c-xxxxx",
			clusterNamespace: "fleet-default",
			clusterExists:    false,
			want:             false,
		},
		{
			name:             "suffix matches c-xxxxx and cluster exists",
			clusterName:      "logic-xxxxx",
			clusterNamespace: "fleet-local",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "prefix matches c-xxxxx and cluster exists",
			clusterName:      "c-aaaaab",
			clusterNamespace: "fleet-default",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "substring matches c-xxxxx and cluster exists",
			clusterName:      "logic-1a3c5bool",
			clusterNamespace: "cattle-system",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "substring matches c-xxxxx and cluster does not exist",
			clusterName:      "logic-1a3c5bool",
			clusterNamespace: "cattle-system",
			clusterExists:    false,
			want:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidName(tt.clusterName, tt.clusterNamespace, tt.clusterExists); got != tt.want {
				t.Errorf("isValidName() = %v, want %v", got, tt.want)
			}
		})
	}
}
