package cluster

import (
	"testing"
)

func TestNormalizeEKSStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected ClusterStatus
	}{
		{
			name:     "active",
			status:   "ACTIVE",
			expected: ClusterStatusReady,
		},
		{
			name:     "creating",
			status:   "CREATING",
			expected: ClusterStatusCreating,
		},
		{
			name:     "updating",
			status:   "UPDATING",
			expected: ClusterStatusUpdating,
		},
		{
			name:     "deleting",
			status:   "DELETING",
			expected: ClusterStatusDeleting,
		},
		{
			name:     "failed",
			status:   "FAILED",
			expected: ClusterStatusError,
		},
		{
			name:     "pending",
			status:   "PENDING",
			expected: ClusterStatusCreating,
		},
		{
			name:     "unknown status",
			status:   "SOMETHING_ELSE",
			expected: ClusterStatusUnknown,
		},
		{
			name:     "empty status",
			status:   "",
			expected: ClusterStatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeEKSStatus(tt.status)
			if result != tt.expected {
				t.Errorf("NormalizeEKSStatus(%q) = %q, want %q", tt.status, result, tt.expected)
			}
		})
	}
}

func TestNormalizeGKEStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected ClusterStatus
	}{
		{
			name:     "running",
			status:   "RUNNING",
			expected: ClusterStatusReady,
		},
		{
			name:     "provisioning",
			status:   "PROVISIONING",
			expected: ClusterStatusCreating,
		},
		{
			name:     "reconciling",
			status:   "RECONCILING",
			expected: ClusterStatusUpdating,
		},
		{
			name:     "stopping",
			status:   "STOPPING",
			expected: ClusterStatusDeleting,
		},
		{
			name:     "error",
			status:   "ERROR",
			expected: ClusterStatusError,
		},
		{
			name:     "degraded",
			status:   "DEGRADED",
			expected: ClusterStatusError,
		},
		{
			name:     "status unspecified",
			status:   "STATUS_UNSPECIFIED",
			expected: ClusterStatusUnknown,
		},
		{
			name:     "unknown status",
			status:   "SOMETHING_ELSE",
			expected: ClusterStatusUnknown,
		},
		{
			name:     "empty status",
			status:   "",
			expected: ClusterStatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeGKEStatus(tt.status)
			if result != tt.expected {
				t.Errorf("NormalizeGKEStatus(%q) = %q, want %q", tt.status, result, tt.expected)
			}
		})
	}
}

func TestNormalizeAKSStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected ClusterStatus
	}{
		{
			name:     "succeeded",
			status:   "Succeeded",
			expected: ClusterStatusReady,
		},
		{
			name:     "creating",
			status:   "Creating",
			expected: ClusterStatusCreating,
		},
		{
			name:     "updating",
			status:   "Updating",
			expected: ClusterStatusUpdating,
		},
		{
			name:     "deleting",
			status:   "Deleting",
			expected: ClusterStatusDeleting,
		},
		{
			name:     "failed",
			status:   "Failed",
			expected: ClusterStatusError,
		},
		{
			name:     "canceled",
			status:   "Canceled",
			expected: ClusterStatusError,
		},
		{
			name:     "unknown status",
			status:   "SomethingElse",
			expected: ClusterStatusUnknown,
		},
		{
			name:     "empty status",
			status:   "",
			expected: ClusterStatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeAKSStatus(tt.status)
			if result != tt.expected {
				t.Errorf("NormalizeAKSStatus(%q) = %q, want %q", tt.status, result, tt.expected)
			}
		})
	}
}

func TestClusterStatusIsReady(t *testing.T) {
	tests := []struct {
		status   ClusterStatus
		expected bool
	}{
		{ClusterStatusReady, true},
		{ClusterStatusCreating, false},
		{ClusterStatusUpdating, false},
		{ClusterStatusDeleting, false},
		{ClusterStatusError, false},
		{ClusterStatusUnknown, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := tt.status.IsReady()
			if result != tt.expected {
				t.Errorf("ClusterStatus(%q).IsReady() = %v, want %v", tt.status, result, tt.expected)
			}
		})
	}
}

func TestClusterStatusIsTransitioning(t *testing.T) {
	tests := []struct {
		status   ClusterStatus
		expected bool
	}{
		{ClusterStatusReady, false},
		{ClusterStatusCreating, true},
		{ClusterStatusUpdating, true},
		{ClusterStatusDeleting, true},
		{ClusterStatusError, false},
		{ClusterStatusUnknown, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := tt.status.IsTransitioning()
			if result != tt.expected {
				t.Errorf("ClusterStatus(%q).IsTransitioning() = %v, want %v", tt.status, result, tt.expected)
			}
		})
	}
}

func TestClusterStatusIsError(t *testing.T) {
	tests := []struct {
		status   ClusterStatus
		expected bool
	}{
		{ClusterStatusReady, false},
		{ClusterStatusCreating, false},
		{ClusterStatusUpdating, false},
		{ClusterStatusDeleting, false},
		{ClusterStatusError, true},
		{ClusterStatusUnknown, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := tt.status.IsError()
			if result != tt.expected {
				t.Errorf("ClusterStatus(%q).IsError() = %v, want %v", tt.status, result, tt.expected)
			}
		})
	}
}

func TestClusterStatusConstants(t *testing.T) {
	// Verify status string values
	tests := []struct {
		status   ClusterStatus
		expected string
	}{
		{ClusterStatusReady, "ready"},
		{ClusterStatusCreating, "creating"},
		{ClusterStatusUpdating, "updating"},
		{ClusterStatusDeleting, "deleting"},
		{ClusterStatusError, "error"},
		{ClusterStatusUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.status) != tt.expected {
				t.Errorf("ClusterStatus constant %q has value %q, want %q", tt.expected, string(tt.status), tt.expected)
			}
		})
	}
}

func TestClusterInfoWithNormalizedStatus(t *testing.T) {
	info := ClusterInfo{
		Name:             "test-cluster",
		Type:             ClusterTypeEKS,
		Status:           "ACTIVE",
		NormalizedStatus: NormalizeEKSStatus("ACTIVE"),
	}

	if info.NormalizedStatus != ClusterStatusReady {
		t.Errorf("expected NormalizedStatus to be %q, got %q", ClusterStatusReady, info.NormalizedStatus)
	}

	if !info.NormalizedStatus.IsReady() {
		t.Error("expected IsReady() to return true")
	}
}
