package k8s

import (
	"testing"
)

func TestK8sOperationStruct(t *testing.T) {
	op := K8sOperation{
		Operation:  "list_pods",
		Reason:     "User requested pod listing",
		Parameters: map[string]interface{}{"namespace": "default"},
	}

	if op.Operation != "list_pods" {
		t.Errorf("expected Operation 'list_pods', got %q", op.Operation)
	}
	if op.Reason != "User requested pod listing" {
		t.Errorf("expected Reason 'User requested pod listing', got %q", op.Reason)
	}
	if op.Parameters == nil {
		t.Error("expected non-nil Parameters")
	}
	if op.Parameters["namespace"] != "default" {
		t.Errorf("expected namespace 'default', got %v", op.Parameters["namespace"])
	}
}

func TestK8sAnalysisStruct(t *testing.T) {
	analysis := K8sAnalysis{
		Operations: []K8sOperation{
			{Operation: "list_pods", Reason: "Get pod list"},
			{Operation: "list_services", Reason: "Get service list"},
		},
		Analysis: "Analyzing cluster workloads",
	}

	if len(analysis.Operations) != 2 {
		t.Errorf("expected 2 operations, got %d", len(analysis.Operations))
	}
	if analysis.Operations[0].Operation != "list_pods" {
		t.Errorf("expected first operation 'list_pods', got %q", analysis.Operations[0].Operation)
	}
	if analysis.Analysis != "Analyzing cluster workloads" {
		t.Errorf("expected Analysis 'Analyzing cluster workloads', got %q", analysis.Analysis)
	}
}

func TestK8sOperationResultStruct(t *testing.T) {
	result := K8sOperationResult{
		Operation: "list_pods",
		Result:    "NAME    READY   STATUS\nnginx   1/1     Running",
		Error:     nil,
		Index:     0,
	}

	if result.Operation != "list_pods" {
		t.Errorf("expected Operation 'list_pods', got %q", result.Operation)
	}
	if result.Result == "" {
		t.Error("expected non-empty Result")
	}
	if result.Error != nil {
		t.Errorf("expected nil Error, got %v", result.Error)
	}
	if result.Index != 0 {
		t.Errorf("expected Index 0, got %d", result.Index)
	}
}

func TestGetStringParam(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		params   map[string]interface{}
		key      string
		defVal   string
		expected string
	}{
		{
			name:     "nil params",
			params:   nil,
			key:      "namespace",
			defVal:   "default",
			expected: "default",
		},
		{
			name:     "key exists",
			params:   map[string]interface{}{"namespace": "kube-system"},
			key:      "namespace",
			defVal:   "default",
			expected: "kube-system",
		},
		{
			name:     "key missing",
			params:   map[string]interface{}{"other": "value"},
			key:      "namespace",
			defVal:   "default",
			expected: "default",
		},
		{
			name:     "empty string value",
			params:   map[string]interface{}{"namespace": ""},
			key:      "namespace",
			defVal:   "default",
			expected: "default",
		},
		{
			name:     "wrong type",
			params:   map[string]interface{}{"namespace": 123},
			key:      "namespace",
			defVal:   "default",
			expected: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.getStringParam(tt.params, tt.key, tt.defVal)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetBoolParam(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		params   map[string]interface{}
		key      string
		defVal   bool
		expected bool
	}{
		{
			name:     "nil params",
			params:   nil,
			key:      "all_namespaces",
			defVal:   false,
			expected: false,
		},
		{
			name:     "key exists true",
			params:   map[string]interface{}{"all_namespaces": true},
			key:      "all_namespaces",
			defVal:   false,
			expected: true,
		},
		{
			name:     "key exists false",
			params:   map[string]interface{}{"all_namespaces": false},
			key:      "all_namespaces",
			defVal:   true,
			expected: false,
		},
		{
			name:     "key missing",
			params:   map[string]interface{}{"other": true},
			key:      "all_namespaces",
			defVal:   false,
			expected: false,
		},
		{
			name:     "wrong type",
			params:   map[string]interface{}{"all_namespaces": "true"},
			key:      "all_namespaces",
			defVal:   false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.getBoolParam(tt.params, tt.key, tt.defVal)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetIntParam(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		params   map[string]interface{}
		key      string
		defVal   int
		expected int
	}{
		{
			name:     "nil params",
			params:   nil,
			key:      "tail_lines",
			defVal:   100,
			expected: 100,
		},
		{
			name:     "key exists as float64",
			params:   map[string]interface{}{"tail_lines": float64(50)},
			key:      "tail_lines",
			defVal:   100,
			expected: 50,
		},
		{
			name:     "key exists as int",
			params:   map[string]interface{}{"tail_lines": 75},
			key:      "tail_lines",
			defVal:   100,
			expected: 75,
		},
		{
			name:     "key missing",
			params:   map[string]interface{}{"other": 123},
			key:      "tail_lines",
			defVal:   100,
			expected: 100,
		},
		{
			name:     "wrong type",
			params:   map[string]interface{}{"tail_lines": "50"},
			key:      "tail_lines",
			defVal:   100,
			expected: 100,
		},
		{
			name:     "zero value float64",
			params:   map[string]interface{}{"tail_lines": float64(0)},
			key:      "tail_lines",
			defVal:   100,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.getIntParam(tt.params, tt.key, tt.defVal)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestFormatNodeList(t *testing.T) {
	tests := []struct {
		name     string
		nodes    []NodeInfo
		contains []string
	}{
		{
			name:     "empty list",
			nodes:    []NodeInfo{},
			contains: []string{"No nodes found"},
		},
		{
			name: "single node",
			nodes: []NodeInfo{
				{
					Name:       "node-1",
					Role:       "control-plane",
					Status:     "Ready",
					InternalIP: "10.0.0.1",
					ExternalIP: "203.0.113.1",
				},
			},
			contains: []string{"NAME", "ROLE", "STATUS", "INTERNAL-IP", "EXTERNAL-IP", "node-1", "control-plane", "Ready", "10.0.0.1", "203.0.113.1"},
		},
		{
			name: "node without external IP",
			nodes: []NodeInfo{
				{
					Name:       "worker-1",
					Role:       "worker",
					Status:     "Ready",
					InternalIP: "10.0.0.2",
					ExternalIP: "",
				},
			},
			contains: []string{"worker-1", "<none>"},
		},
		{
			name: "multiple nodes",
			nodes: []NodeInfo{
				{
					Name:       "control-1",
					Role:       "control-plane",
					Status:     "Ready",
					InternalIP: "10.0.0.1",
					ExternalIP: "203.0.113.1",
				},
				{
					Name:       "worker-1",
					Role:       "worker",
					Status:     "Ready",
					InternalIP: "10.0.0.2",
					ExternalIP: "",
				},
			},
			contains: []string{"control-1", "worker-1", "control-plane", "worker"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatNodeList(tt.nodes)
			for _, substr := range tt.contains {
				if !contains(result, substr) {
					t.Errorf("expected result to contain %q, got %q", substr, result)
				}
			}
		})
	}
}

func TestK8sOperationWithComplexParameters(t *testing.T) {
	op := K8sOperation{
		Operation: "get_pod_logs",
		Reason:    "Debug pod issues",
		Parameters: map[string]interface{}{
			"name":       "nginx-pod",
			"namespace":  "production",
			"tail_lines": float64(200),
			"since":      "1h",
			"container":  "nginx",
		},
	}

	if op.Operation != "get_pod_logs" {
		t.Errorf("expected Operation 'get_pod_logs', got %q", op.Operation)
	}

	// Verify parameter types
	if _, ok := op.Parameters["name"].(string); !ok {
		t.Error("expected 'name' to be a string")
	}
	if _, ok := op.Parameters["tail_lines"].(float64); !ok {
		t.Error("expected 'tail_lines' to be a float64")
	}
}

func TestK8sAnalysisWithMultipleOperations(t *testing.T) {
	analysis := K8sAnalysis{
		Operations: []K8sOperation{
			{
				Operation: "list_pods",
				Reason:    "Get all pods",
				Parameters: map[string]interface{}{
					"all_namespaces": true,
				},
			},
			{
				Operation: "get_events",
				Reason:    "Check for issues",
				Parameters: map[string]interface{}{
					"namespace": "kube-system",
				},
			},
			{
				Operation:  "get_node_metrics",
				Reason:     "Check resource usage",
				Parameters: map[string]interface{}{},
			},
		},
		Analysis: "Investigating cluster health",
	}

	if len(analysis.Operations) != 3 {
		t.Errorf("expected 3 operations, got %d", len(analysis.Operations))
	}

	// Verify each operation
	expectedOps := []string{"list_pods", "get_events", "get_node_metrics"}
	for i, expectedOp := range expectedOps {
		if analysis.Operations[i].Operation != expectedOp {
			t.Errorf("operation %d: expected %q, got %q", i, expectedOp, analysis.Operations[i].Operation)
		}
	}
}

func TestK8sOperationResultWithError(t *testing.T) {
	result := K8sOperationResult{
		Operation: "get_pod_details",
		Result:    "",
		Error:     errTest,
		Index:     1,
	}

	if result.Operation != "get_pod_details" {
		t.Errorf("expected Operation 'get_pod_details', got %q", result.Operation)
	}
	if result.Result != "" {
		t.Errorf("expected empty Result, got %q", result.Result)
	}
	if result.Error == nil {
		t.Error("expected non-nil Error")
	}
	if result.Index != 1 {
		t.Errorf("expected Index 1, got %d", result.Index)
	}
}

var errTest = newTestError("test error")

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func newTestError(msg string) error {
	return &testError{msg: msg}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestOperationNames(t *testing.T) {
	// Test that common operation names are valid strings
	operations := []string{
		"get_cluster_info",
		"get_nodes",
		"get_node_details",
		"get_namespaces",
		"get_cluster_version",
		"get_contexts",
		"get_current_context",
		"list_pods",
		"get_pod_details",
		"list_deployments",
		"get_deployment_details",
		"list_statefulsets",
		"list_daemonsets",
		"list_replicasets",
		"list_jobs",
		"list_cronjobs",
		"list_services",
		"get_service_details",
		"list_ingresses",
		"get_ingress_details",
		"list_endpoints",
		"list_network_policies",
		"list_pvs",
		"list_pvcs",
		"list_storage_classes",
		"list_configmaps",
		"get_configmap_details",
		"list_secrets",
		"get_pod_logs",
		"get_events",
		"get_recent_events",
		"get_warning_events",
		"get_node_metrics",
		"get_top_nodes",
		"get_pod_metrics",
		"get_top_pods",
		"list_helm_releases",
		"get_release_details",
		"list_helm_repos",
		"describe_resource",
		"get_pod_containers",
		"check_pod_errors",
		"get_unhealthy_pods",
		"get_pending_pods",
	}

	for _, op := range operations {
		if op == "" {
			t.Error("empty operation name")
		}
		// Verify operation name follows convention
		if op[0] < 'a' || op[0] > 'z' {
			t.Errorf("operation %q should start with lowercase letter", op)
		}
	}
}

func TestEmptyParameters(t *testing.T) {
	client := &Client{}

	// Test with empty parameters map
	params := map[string]interface{}{}

	strResult := client.getStringParam(params, "namespace", "default")
	if strResult != "default" {
		t.Errorf("expected 'default', got %q", strResult)
	}

	boolResult := client.getBoolParam(params, "all_namespaces", false)
	if boolResult != false {
		t.Errorf("expected false, got %v", boolResult)
	}

	intResult := client.getIntParam(params, "tail_lines", 100)
	if intResult != 100 {
		t.Errorf("expected 100, got %d", intResult)
	}
}

func TestNodeInfoFormatting(t *testing.T) {
	nodes := []NodeInfo{
		{
			Name:       "node-with-long-name",
			Role:       "control-plane,master",
			Status:     "Ready",
			InternalIP: "192.168.1.100",
			ExternalIP: "35.123.45.67",
		},
	}

	result := formatNodeList(nodes)

	// Verify header is present
	if !contains(result, "NAME") {
		t.Error("missing NAME header")
	}
	if !contains(result, "ROLE") {
		t.Error("missing ROLE header")
	}
	if !contains(result, "STATUS") {
		t.Error("missing STATUS header")
	}
	if !contains(result, "INTERNAL-IP") {
		t.Error("missing INTERNAL-IP header")
	}
	if !contains(result, "EXTERNAL-IP") {
		t.Error("missing EXTERNAL-IP header")
	}

	// Verify node data is present
	if !contains(result, "node-with-long-name") {
		t.Error("missing node name")
	}
	if !contains(result, "control-plane,master") {
		t.Error("missing node role")
	}
}
