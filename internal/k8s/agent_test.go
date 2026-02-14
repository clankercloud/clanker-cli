package k8s

import (
	"context"
	"testing"

	"github.com/bgdnvk/clanker/internal/k8s/cluster"
)

func TestNewAgent(t *testing.T) {
	tests := []struct {
		name  string
		debug bool
	}{
		{
			name:  "with debug enabled",
			debug: true,
		},
		{
			name:  "with debug disabled",
			debug: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := NewAgent(tt.debug)
			if agent == nil {
				t.Fatal("expected non-nil agent")
			}
			if agent.debug != tt.debug {
				t.Errorf("expected debug=%v, got %v", tt.debug, agent.debug)
			}
			if agent.clusterMgr == nil {
				t.Error("expected non-nil cluster manager")
			}
		})
	}
}

func TestNewAgentWithOptions(t *testing.T) {
	tests := []struct {
		name string
		opts AgentOptions
	}{
		{
			name: "empty options",
			opts: AgentOptions{},
		},
		{
			name: "with debug only",
			opts: AgentOptions{
				Debug: true,
			},
		},
		{
			name: "with AWS profile",
			opts: AgentOptions{
				AWSProfile: "my-profile",
				Region:     "us-west-2",
				Debug:      true,
			},
		},
		{
			name: "with kubeconfig",
			opts: AgentOptions{
				Kubeconfig: "~/.kube/config",
			},
		},
		{
			name: "with all options",
			opts: AgentOptions{
				Debug:      true,
				AWSProfile: "production",
				Region:     "eu-west-1",
				Kubeconfig: "/path/to/kubeconfig",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := NewAgentWithOptions(tt.opts)
			if agent == nil {
				t.Fatal("expected non-nil agent")
			}
			if agent.debug != tt.opts.Debug {
				t.Errorf("expected debug=%v, got %v", tt.opts.Debug, agent.debug)
			}
			if agent.clusterMgr == nil {
				t.Error("expected non-nil cluster manager")
			}

			// Check that existing provider is always registered
			_, hasExisting := agent.clusterMgr.GetProvider(ClusterTypeExisting)
			if !hasExisting {
				t.Error("expected existing provider to be registered")
			}

			// Check that EKS provider is registered when profile or region is set
			_, hasEKS := agent.clusterMgr.GetProvider(ClusterTypeEKS)
			expectEKS := tt.opts.AWSProfile != "" || tt.opts.Region != ""
			if hasEKS != expectEKS {
				t.Errorf("expected EKS provider registered=%v, got %v", expectEKS, hasEKS)
			}
		})
	}
}

func TestAgentOptions(t *testing.T) {
	opts := AgentOptions{
		Debug:      true,
		AWSProfile: "test-profile",
		Region:     "us-east-1",
		Kubeconfig: "/custom/kubeconfig",
	}

	if !opts.Debug {
		t.Error("expected Debug to be true")
	}
	if opts.AWSProfile != "test-profile" {
		t.Errorf("expected AWSProfile 'test-profile', got %q", opts.AWSProfile)
	}
	if opts.Region != "us-east-1" {
		t.Errorf("expected Region 'us-east-1', got %q", opts.Region)
	}
	if opts.Kubeconfig != "/custom/kubeconfig" {
		t.Errorf("expected Kubeconfig '/custom/kubeconfig', got %q", opts.Kubeconfig)
	}
}

func TestKubeadmProviderOptions(t *testing.T) {
	opts := KubeadmProviderOptions{
		AWSProfile:  "kubeadm-profile",
		Region:      "us-west-2",
		VPCID:       "vpc-12345",
		SubnetID:    "subnet-67890",
		KeyPairName: "my-keypair",
		SSHKeyPath:  "~/.ssh/id_rsa",
	}

	if opts.AWSProfile != "kubeadm-profile" {
		t.Errorf("expected AWSProfile 'kubeadm-profile', got %q", opts.AWSProfile)
	}
	if opts.Region != "us-west-2" {
		t.Errorf("expected Region 'us-west-2', got %q", opts.Region)
	}
	if opts.VPCID != "vpc-12345" {
		t.Errorf("expected VPCID 'vpc-12345', got %q", opts.VPCID)
	}
	if opts.SubnetID != "subnet-67890" {
		t.Errorf("expected SubnetID 'subnet-67890', got %q", opts.SubnetID)
	}
	if opts.KeyPairName != "my-keypair" {
		t.Errorf("expected KeyPairName 'my-keypair', got %q", opts.KeyPairName)
	}
	if opts.SSHKeyPath != "~/.ssh/id_rsa" {
		t.Errorf("expected SSHKeyPath '~/.ssh/id_rsa', got %q", opts.SSHKeyPath)
	}
}

func TestRegisterEKSProvider(t *testing.T) {
	agent := NewAgent(false)

	// Initially EKS provider should not be registered (no profile/region in NewAgent)
	_, hasEKS := agent.clusterMgr.GetProvider(ClusterTypeEKS)
	if hasEKS {
		t.Error("expected EKS provider not to be registered initially")
	}

	// Register EKS provider
	agent.RegisterEKSProvider("my-profile", "us-west-2")

	// Now EKS provider should be registered
	provider, hasEKS := agent.clusterMgr.GetProvider(ClusterTypeEKS)
	if !hasEKS {
		t.Error("expected EKS provider to be registered")
	}
	if provider == nil {
		t.Error("expected non-nil provider")
	}
	if provider.Type() != ClusterTypeEKS {
		t.Errorf("expected provider type EKS, got %s", provider.Type())
	}
}

func TestRegisterGKEProvider(t *testing.T) {
	agent := NewAgent(false)

	// Initially GKE provider should not be registered
	_, hasGKE := agent.clusterMgr.GetProvider(ClusterTypeGKE)
	if hasGKE {
		t.Error("expected GKE provider not to be registered initially")
	}

	// Register GKE provider
	agent.RegisterGKEProvider("my-gcp-project", "us-central1")

	// Now GKE provider should be registered
	provider, hasGKE := agent.clusterMgr.GetProvider(ClusterTypeGKE)
	if !hasGKE {
		t.Error("expected GKE provider to be registered")
	}
	if provider == nil {
		t.Error("expected non-nil provider")
	}
	if provider.Type() != ClusterTypeGKE {
		t.Errorf("expected provider type GKE, got %s", provider.Type())
	}
}

func TestRegisterAKSProvider(t *testing.T) {
	agent := NewAgent(false)

	// Initially AKS provider should not be registered
	_, hasAKS := agent.clusterMgr.GetProvider(ClusterTypeAKS)
	if hasAKS {
		t.Error("expected AKS provider not to be registered initially")
	}

	// Register AKS provider
	agent.RegisterAKSProvider("subscription-id", "my-resource-group", "eastus")

	// Now AKS provider should be registered
	provider, hasAKS := agent.clusterMgr.GetProvider(ClusterTypeAKS)
	if !hasAKS {
		t.Error("expected AKS provider to be registered")
	}
	if provider == nil {
		t.Error("expected non-nil provider")
	}
	if provider.Type() != ClusterTypeAKS {
		t.Errorf("expected provider type AKS, got %s", provider.Type())
	}
}

func TestRegisterKubeadmProvider(t *testing.T) {
	agent := NewAgent(false)

	// Initially kubeadm provider should not be registered
	_, hasKubeadm := agent.clusterMgr.GetProvider(ClusterTypeKubeadm)
	if hasKubeadm {
		t.Error("expected kubeadm provider not to be registered initially")
	}

	// Register kubeadm provider
	opts := KubeadmProviderOptions{
		AWSProfile:  "kubeadm-profile",
		Region:      "us-west-2",
		VPCID:       "vpc-12345",
		SubnetID:    "subnet-67890",
		KeyPairName: "my-keypair",
		SSHKeyPath:  "~/.ssh/id_rsa",
	}
	agent.RegisterKubeadmProvider(opts)

	// Now kubeadm provider should be registered
	provider, hasKubeadm := agent.clusterMgr.GetProvider(ClusterTypeKubeadm)
	if !hasKubeadm {
		t.Error("expected kubeadm provider to be registered")
	}
	if provider == nil {
		t.Error("expected non-nil provider")
	}
	if provider.Type() != ClusterTypeKubeadm {
		t.Errorf("expected provider type kubeadm, got %s", provider.Type())
	}
}

func TestRegisterClusterProvider(t *testing.T) {
	agent := NewAgent(false)

	// Create a mock provider (using existing provider as an example)
	mockProvider := cluster.NewExistingProvider("~/.kube/config", false)

	// Register the provider
	agent.RegisterClusterProvider(mockProvider)

	// Verify the provider is registered
	provider, ok := agent.GetClusterProvider(ClusterTypeExisting)
	if !ok {
		t.Error("expected provider to be registered")
	}
	if provider == nil {
		t.Error("expected non-nil provider")
	}
}

func TestSetAIDecisionFunction(t *testing.T) {
	agent := NewAgent(false)

	// Initially AI decision function should be nil
	if agent.aiDecisionFn != nil {
		t.Error("expected aiDecisionFn to be nil initially")
	}

	// Set AI decision function
	called := false
	fn := func(ctx context.Context, prompt string) (string, error) {
		called = true
		return "test response", nil
	}
	agent.SetAIDecisionFunction(fn)

	// Verify function is set
	if agent.aiDecisionFn == nil {
		t.Error("expected aiDecisionFn to be set")
	}

	// Call the function to verify it works
	result, err := agent.aiDecisionFn(context.Background(), "test prompt")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "test response" {
		t.Errorf("expected 'test response', got %q", result)
	}
	if !called {
		t.Error("expected function to be called")
	}
}

func TestSetClient(t *testing.T) {
	agent := NewAgent(false)

	// Initially client should be nil
	if agent.client != nil {
		t.Error("expected client to be nil initially")
	}

	// Create and set client
	client := NewClient("~/.kube/config", "my-context", false)
	agent.SetClient(client)

	// Verify client is set
	if agent.client == nil {
		t.Error("expected client to be set")
	}
	if agent.client != client {
		t.Error("expected client to match the one that was set")
	}
}

func TestCheckDependencies(t *testing.T) {
	agent := NewAgent(false)

	// CheckDependencies should return a slice of dependency statuses
	statuses := agent.CheckDependencies()
	if statuses == nil {
		t.Error("expected non-nil statuses")
	}

	// Should have at least kubectl in the list
	hasKubectl := false
	for _, status := range statuses {
		if status.Name == "kubectl" {
			hasKubectl = true
			break
		}
	}
	if !hasKubectl {
		t.Error("expected kubectl to be in dependency list")
	}
}

func TestGetClusterProvider(t *testing.T) {
	agent := NewAgent(false)

	// Existing provider should be registered by default
	provider, ok := agent.GetClusterProvider(ClusterTypeExisting)
	if !ok {
		t.Error("expected existing provider to be registered")
	}
	if provider == nil {
		t.Error("expected non-nil provider")
	}

	// EKS provider should not be registered by default (no profile/region)
	_, ok = agent.GetClusterProvider(ClusterTypeEKS)
	if ok {
		t.Error("expected EKS provider not to be registered by default")
	}

	// GKE provider should not be registered by default
	_, ok = agent.GetClusterProvider(ClusterTypeGKE)
	if ok {
		t.Error("expected GKE provider not to be registered by default")
	}

	// AKS provider should not be registered by default
	_, ok = agent.GetClusterProvider(ClusterTypeAKS)
	if ok {
		t.Error("expected AKS provider not to be registered by default")
	}
}

func TestQueryAnalysis(t *testing.T) {
	agent := NewAgent(false)

	tests := []struct {
		name               string
		query              string
		expectReadOnly     bool
		expectCategory     string
		expectClusterScope bool
	}{
		{
			name:           "list pods query",
			query:          "list all pods",
			expectReadOnly: true,
			expectCategory: "workloads",
		},
		{
			name:           "get deployments query",
			query:          "show me the deployments",
			expectReadOnly: false, // "deployments" contains "deploy" which is a modify pattern
			expectCategory: "workloads",
		},
		{
			name:           "describe service query",
			query:          "describe the nginx service",
			expectReadOnly: true,
			expectCategory: "networking",
		},
		{
			name:           "create deployment query",
			query:          "create a deployment called nginx",
			expectReadOnly: false,
			expectCategory: "workloads",
		},
		{
			name:           "delete pod query",
			query:          "delete the failing pod",
			expectReadOnly: false,
			expectCategory: "workloads",
		},
		{
			name:           "scale deployment query",
			query:          "scale the deployment to 5 replicas",
			expectReadOnly: false,
			expectCategory: "workloads",
		},
		{
			name:               "cluster nodes query",
			query:              "show cluster nodes",
			expectReadOnly:     true,
			expectClusterScope: true,
		},
		{
			name:           "helm install query",
			query:          "install nginx helm chart",
			expectReadOnly: false,
			expectCategory: "helm",
		},
		{
			name:           "helm list query",
			query:          "list helm releases",
			expectReadOnly: true,
			expectCategory: "helm",
		},
		{
			name:           "pvc storage query",
			query:          "list persistent volume claims",
			expectReadOnly: true,
			expectCategory: "storage",
		},
		{
			name:           "network policy query",
			query:          "show network policies",
			expectReadOnly: true,
			expectCategory: "networking",
		},
		{
			name:           "logs query",
			query:          "show logs for pod nginx",
			expectReadOnly: true,
			expectCategory: "workloads", // "pod" triggers workloads category before sre
		},
		{
			name:           "metrics query",
			query:          "show resource metrics",
			expectReadOnly: true,
			expectCategory: "telemetry",
		},
		{
			name:           "health check query",
			query:          "check health of the system",
			expectReadOnly: true,
			expectCategory: "sre",
		},
		{
			name:               "create cluster query",
			query:              "create a new EKS cluster",
			expectReadOnly:     false,
			expectCategory:     "cluster_provisioning",
			expectClusterScope: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := agent.analyzeQuery(tt.query)

			if analysis.IsReadOnly != tt.expectReadOnly {
				t.Errorf("expected IsReadOnly=%v, got %v", tt.expectReadOnly, analysis.IsReadOnly)
			}
			if tt.expectCategory != "" && analysis.Category != tt.expectCategory {
				t.Errorf("expected Category=%q, got %q", tt.expectCategory, analysis.Category)
			}
			if analysis.ClusterScope != tt.expectClusterScope {
				t.Errorf("expected ClusterScope=%v, got %v", tt.expectClusterScope, analysis.ClusterScope)
			}
		})
	}
}

func TestQueryAnalysisNamespaceHint(t *testing.T) {
	agent := NewAgent(false)

	tests := []struct {
		name       string
		query      string
		expectHint string
	}{
		{
			name:       "kube-system namespace",
			query:      "list pods in kube-system",
			expectHint: "kube-system",
		},
		{
			name:       "default namespace explicit",
			query:      "show pods in default namespace",
			expectHint: "default",
		},
		{
			name:       "no namespace hint",
			query:      "list all pods",
			expectHint: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := agent.analyzeQuery(tt.query)
			if analysis.NamespaceHint != tt.expectHint {
				t.Errorf("expected NamespaceHint=%q, got %q", tt.expectHint, analysis.NamespaceHint)
			}
		})
	}
}

func TestAgentCloudProviderConstants(t *testing.T) {
	tests := []struct {
		name     string
		provider CloudProvider
		expected string
	}{
		{
			name:     "unknown provider",
			provider: CloudProviderUnknown,
			expected: "",
		},
		{
			name:     "AWS provider",
			provider: CloudProviderAWS,
			expected: "aws",
		},
		{
			name:     "GCP provider",
			provider: CloudProviderGCP,
			expected: "gcp",
		},
		{
			name:     "Azure provider",
			provider: CloudProviderAzure,
			expected: "azure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.provider) != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, string(tt.provider))
			}
		})
	}
}

func TestResponseTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		respType ResponseType
		expected string
	}{
		{
			name:     "plan response",
			respType: ResponseTypePlan,
			expected: "plan",
		},
		{
			name:     "result response",
			respType: ResponseTypeResult,
			expected: "result",
		},
		{
			name:     "error response",
			respType: ResponseTypeError,
			expected: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.respType) != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, string(tt.respType))
			}
		})
	}
}

func TestQueryOptions(t *testing.T) {
	opts := QueryOptions{
		ClusterName:   "my-cluster",
		ClusterType:   ClusterTypeEKS,
		Namespace:     "production",
		AWSProfile:    "prod-profile",
		GCPProject:    "my-gcp-project",
		Region:        "us-west-2",
		MakerMode:     true,
		Kubeconfig:    "~/.kube/config",
		CloudProvider: CloudProviderAWS,
	}

	if opts.ClusterName != "my-cluster" {
		t.Errorf("expected ClusterName 'my-cluster', got %q", opts.ClusterName)
	}
	if opts.ClusterType != ClusterTypeEKS {
		t.Errorf("expected ClusterType EKS, got %s", opts.ClusterType)
	}
	if opts.Namespace != "production" {
		t.Errorf("expected Namespace 'production', got %q", opts.Namespace)
	}
	if opts.AWSProfile != "prod-profile" {
		t.Errorf("expected AWSProfile 'prod-profile', got %q", opts.AWSProfile)
	}
	if opts.GCPProject != "my-gcp-project" {
		t.Errorf("expected GCPProject 'my-gcp-project', got %q", opts.GCPProject)
	}
	if opts.Region != "us-west-2" {
		t.Errorf("expected Region 'us-west-2', got %q", opts.Region)
	}
	if !opts.MakerMode {
		t.Error("expected MakerMode to be true")
	}
	if opts.Kubeconfig != "~/.kube/config" {
		t.Errorf("expected Kubeconfig '~/.kube/config', got %q", opts.Kubeconfig)
	}
	if opts.CloudProvider != CloudProviderAWS {
		t.Errorf("expected CloudProvider AWS, got %s", opts.CloudProvider)
	}
}

func TestApplyOptions(t *testing.T) {
	opts := ApplyOptions{
		Debug:   true,
		DryRun:  true,
		Force:   false,
		Wait:    true,
		Timeout: 300,
	}

	if !opts.Debug {
		t.Error("expected Debug to be true")
	}
	if !opts.DryRun {
		t.Error("expected DryRun to be true")
	}
	if opts.Force {
		t.Error("expected Force to be false")
	}
	if !opts.Wait {
		t.Error("expected Wait to be true")
	}
	if opts.Timeout != 300 {
		t.Errorf("expected Timeout 300, got %d", opts.Timeout)
	}
}

func TestK8sResponse(t *testing.T) {
	resp := K8sResponse{
		Type:          ResponseTypePlan,
		Plan:          &K8sPlan{Summary: "test plan"},
		Result:        "success",
		NeedsApproval: true,
		Summary:       "Test summary",
		Error:         nil,
	}

	if resp.Type != ResponseTypePlan {
		t.Errorf("expected Type 'plan', got %s", resp.Type)
	}
	if resp.Plan == nil {
		t.Error("expected non-nil Plan")
	}
	if resp.Plan.Summary != "test plan" {
		t.Errorf("expected Plan.Summary 'test plan', got %q", resp.Plan.Summary)
	}
	if resp.Result != "success" {
		t.Errorf("expected Result 'success', got %q", resp.Result)
	}
	if !resp.NeedsApproval {
		t.Error("expected NeedsApproval to be true")
	}
	if resp.Summary != "Test summary" {
		t.Errorf("expected Summary 'Test summary', got %q", resp.Summary)
	}
	if resp.Error != nil {
		t.Errorf("expected nil Error, got %v", resp.Error)
	}
}

func TestMultipleProviderRegistration(t *testing.T) {
	agent := NewAgent(true)

	// Register multiple providers
	agent.RegisterEKSProvider("aws-profile", "us-west-2")
	agent.RegisterGKEProvider("gcp-project", "us-central1")
	agent.RegisterAKSProvider("subscription-id", "resource-group", "eastus")

	// Verify all providers are registered
	providers := []ClusterType{
		ClusterTypeExisting,
		ClusterTypeEKS,
		ClusterTypeGKE,
		ClusterTypeAKS,
	}

	for _, ct := range providers {
		provider, ok := agent.GetClusterProvider(ct)
		if !ok {
			t.Errorf("expected %s provider to be registered", ct)
		}
		if provider == nil {
			t.Errorf("expected non-nil provider for %s", ct)
		}
		if provider.Type() != ct {
			t.Errorf("expected provider type %s, got %s", ct, provider.Type())
		}
	}
}

func TestAgentWithDebugOptions(t *testing.T) {
	// Test debug mode propagation
	agent := NewAgentWithOptions(AgentOptions{
		Debug:      true,
		AWSProfile: "test",
		Region:     "us-west-2",
	})

	if !agent.debug {
		t.Error("expected debug to be true")
	}

	// Verify EKS provider is registered with debug
	provider, ok := agent.GetClusterProvider(ClusterTypeEKS)
	if !ok {
		t.Error("expected EKS provider to be registered")
	}
	if provider == nil {
		t.Error("expected non-nil EKS provider")
	}
}
