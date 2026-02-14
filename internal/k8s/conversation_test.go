package k8s

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConversationEntryStruct(t *testing.T) {
	entry := ConversationEntry{
		Timestamp: time.Now(),
		Question:  "How many pods are running?",
		Answer:    "There are 10 pods running.",
		Cluster:   "my-cluster",
	}

	if entry.Question != "How many pods are running?" {
		t.Errorf("expected Question 'How many pods are running?', got %q", entry.Question)
	}
	if entry.Answer != "There are 10 pods running." {
		t.Errorf("expected Answer 'There are 10 pods running.', got %q", entry.Answer)
	}
	if entry.Cluster != "my-cluster" {
		t.Errorf("expected Cluster 'my-cluster', got %q", entry.Cluster)
	}
	if entry.Timestamp.IsZero() {
		t.Error("expected non-zero Timestamp")
	}
}

func TestClusterStatusStruct(t *testing.T) {
	status := ClusterStatus{
		Timestamp:      time.Now(),
		NodeCount:      3,
		PodCount:       25,
		NamespaceCount: 5,
		Version:        "v1.28.0",
		Context:        "my-cluster-context",
	}

	if status.NodeCount != 3 {
		t.Errorf("expected NodeCount 3, got %d", status.NodeCount)
	}
	if status.PodCount != 25 {
		t.Errorf("expected PodCount 25, got %d", status.PodCount)
	}
	if status.NamespaceCount != 5 {
		t.Errorf("expected NamespaceCount 5, got %d", status.NamespaceCount)
	}
	if status.Version != "v1.28.0" {
		t.Errorf("expected Version 'v1.28.0', got %q", status.Version)
	}
	if status.Context != "my-cluster-context" {
		t.Errorf("expected Context 'my-cluster-context', got %q", status.Context)
	}
}

func TestConstants(t *testing.T) {
	if MaxHistoryEntries != 20 {
		t.Errorf("expected MaxHistoryEntries 20, got %d", MaxHistoryEntries)
	}
	if MaxAnswerLengthInContext != 500 {
		t.Errorf("expected MaxAnswerLengthInContext 500, got %d", MaxAnswerLengthInContext)
	}
}

func TestNewConversationHistory(t *testing.T) {
	history := NewConversationHistory("test-cluster")

	if history == nil {
		t.Fatal("expected non-nil history")
	}
	if history.ClusterName != "test-cluster" {
		t.Errorf("expected ClusterName 'test-cluster', got %q", history.ClusterName)
	}
	if len(history.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(history.Entries))
	}
	if history.LastStatus != nil {
		t.Error("expected nil LastStatus")
	}
}

func TestAddEntry(t *testing.T) {
	history := NewConversationHistory("test-cluster")

	history.AddEntry("Question 1", "Answer 1", "cluster-1")

	if len(history.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(history.Entries))
	}
	if history.Entries[0].Question != "Question 1" {
		t.Errorf("expected Question 'Question 1', got %q", history.Entries[0].Question)
	}
	if history.Entries[0].Answer != "Answer 1" {
		t.Errorf("expected Answer 'Answer 1', got %q", history.Entries[0].Answer)
	}
}

func TestAddEntryTrimming(t *testing.T) {
	history := NewConversationHistory("test-cluster")

	// Add more than MaxHistoryEntries
	for i := 0; i < MaxHistoryEntries+5; i++ {
		history.AddEntry("Question", "Answer", "cluster")
	}

	if len(history.Entries) != MaxHistoryEntries {
		t.Errorf("expected %d entries after trimming, got %d", MaxHistoryEntries, len(history.Entries))
	}
}

func TestGetRecentContext(t *testing.T) {
	history := NewConversationHistory("test-cluster")

	// Empty history
	ctx := history.GetRecentContext(5)
	if ctx != "" {
		t.Errorf("expected empty context for empty history, got %q", ctx)
	}

	// Add entries
	history.AddEntry("What pods are running?", "There are 5 pods running.", "cluster")
	history.AddEntry("Show deployments", "nginx deployment is running.", "cluster")

	ctx = history.GetRecentContext(5)

	if !strings.Contains(ctx, "Q: What pods are running?") {
		t.Error("expected context to contain first question")
	}
	if !strings.Contains(ctx, "A: There are 5 pods running.") {
		t.Error("expected context to contain first answer")
	}
	if !strings.Contains(ctx, "Q: Show deployments") {
		t.Error("expected context to contain second question")
	}
}

func TestGetRecentContextLimited(t *testing.T) {
	history := NewConversationHistory("test-cluster")

	// Add 5 entries
	for i := 1; i <= 5; i++ {
		history.AddEntry("Question "+string(rune('0'+i)), "Answer "+string(rune('0'+i)), "cluster")
	}

	// Request only 2 most recent
	ctx := history.GetRecentContext(2)

	// Should contain only last 2 entries
	if !strings.Contains(ctx, "Question 4") {
		t.Error("expected context to contain Question 4")
	}
	if !strings.Contains(ctx, "Question 5") {
		t.Error("expected context to contain Question 5")
	}
	if strings.Contains(ctx, "Question 1") {
		t.Error("expected context NOT to contain Question 1")
	}
}

func TestUpdateClusterStatus(t *testing.T) {
	history := NewConversationHistory("test-cluster")

	if history.GetClusterStatus() != nil {
		t.Error("expected nil status initially")
	}

	status := &ClusterStatus{
		Timestamp:      time.Now(),
		NodeCount:      3,
		PodCount:       10,
		NamespaceCount: 4,
		Version:        "v1.28.0",
		Context:        "my-context",
	}
	history.UpdateClusterStatus(status)

	retrieved := history.GetClusterStatus()
	if retrieved == nil {
		t.Fatal("expected non-nil status after update")
	}
	if retrieved.NodeCount != 3 {
		t.Errorf("expected NodeCount 3, got %d", retrieved.NodeCount)
	}
}

func TestGetClusterStatusContext(t *testing.T) {
	history := NewConversationHistory("test-cluster")

	// Without status
	ctx := history.GetClusterStatusContext()
	if !strings.Contains(ctx, "Not yet gathered") {
		t.Errorf("expected 'Not yet gathered' for nil status, got %q", ctx)
	}

	// With status
	status := &ClusterStatus{
		Timestamp:      time.Now(),
		NodeCount:      3,
		PodCount:       10,
		NamespaceCount: 4,
		Version:        "v1.28.0",
		Context:        "my-context",
	}
	history.UpdateClusterStatus(status)

	ctx = history.GetClusterStatusContext()
	if !strings.Contains(ctx, "Current Context: my-context") {
		t.Error("expected context to contain current context")
	}
	if !strings.Contains(ctx, "Kubernetes Version: v1.28.0") {
		t.Error("expected context to contain version")
	}
	if !strings.Contains(ctx, "Total Nodes: 3") {
		t.Error("expected context to contain node count")
	}
	if !strings.Contains(ctx, "Total Pods: 10") {
		t.Error("expected context to contain pod count")
	}
	if !strings.Contains(ctx, "Total Namespaces: 4") {
		t.Error("expected context to contain namespace count")
	}
}

func TestClear(t *testing.T) {
	history := NewConversationHistory("test-cluster")
	history.AddEntry("Question", "Answer", "cluster")
	history.UpdateClusterStatus(&ClusterStatus{NodeCount: 5})

	if len(history.Entries) != 1 {
		t.Error("expected 1 entry before clear")
	}
	if history.LastStatus == nil {
		t.Error("expected non-nil status before clear")
	}

	history.Clear()

	if len(history.Entries) != 0 {
		t.Errorf("expected 0 entries after clear, got %d", len(history.Entries))
	}
	if history.LastStatus != nil {
		t.Error("expected nil status after clear")
	}
}

func TestSaveAndLoad(t *testing.T) {
	// Use temp directory for test
	tempDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	defer os.Setenv("HOME", oldHome)
	os.Setenv("HOME", tempDir)

	// Create and populate history
	history := NewConversationHistory("test-save-cluster")
	history.AddEntry("Question 1", "Answer 1", "cluster")
	history.AddEntry("Question 2", "Answer 2", "cluster")
	history.UpdateClusterStatus(&ClusterStatus{
		Timestamp:      time.Now(),
		NodeCount:      3,
		PodCount:       10,
		NamespaceCount: 4,
		Version:        "v1.28.0",
		Context:        "my-context",
	})

	// Save
	err := history.Save()
	if err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	// Verify file exists
	expectedPath := filepath.Join(tempDir, ".clanker", "conversations", "k8s_test-save-cluster.json")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Error("expected conversation file to exist")
	}

	// Load into new history
	loadedHistory := NewConversationHistory("test-save-cluster")
	err = loadedHistory.Load()
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if len(loadedHistory.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(loadedHistory.Entries))
	}
	if loadedHistory.Entries[0].Question != "Question 1" {
		t.Errorf("expected first question 'Question 1', got %q", loadedHistory.Entries[0].Question)
	}
	if loadedHistory.LastStatus == nil {
		t.Error("expected non-nil LastStatus")
	}
	if loadedHistory.LastStatus.NodeCount != 3 {
		t.Errorf("expected NodeCount 3, got %d", loadedHistory.LastStatus.NodeCount)
	}
}

func TestLoadNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	defer os.Setenv("HOME", oldHome)
	os.Setenv("HOME", tempDir)

	history := NewConversationHistory("non-existent-cluster")
	err := history.Load()

	// Should not error for non-existent file
	if err != nil {
		t.Errorf("expected nil error for non-existent file, got %v", err)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple name",
			input:    "my-cluster",
			expected: "my-cluster",
		},
		{
			name:     "with slashes",
			input:    "path/to/cluster",
			expected: "path_to_cluster",
		},
		{
			name:     "with backslashes",
			input:    "path\\to\\cluster",
			expected: "path_to_cluster",
		},
		{
			name:     "with colons",
			input:    "cluster:context",
			expected: "cluster_context",
		},
		{
			name:     "with spaces",
			input:    "my cluster name",
			expected: "my_cluster_name",
		},
		{
			name:     "with special chars",
			input:    "test*?\"<>|cluster",
			expected: "test______cluster",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "all special chars",
			input:    "/*\\:?\"<>| ",
			expected: "__________",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTruncateText(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		maxLen   int
		expected string
	}{
		{
			name:     "short text",
			text:     "Hello",
			maxLen:   10,
			expected: "Hello",
		},
		{
			name:     "exact length",
			text:     "Hello",
			maxLen:   5,
			expected: "Hello",
		},
		{
			name:     "long text",
			text:     "Hello World",
			maxLen:   5,
			expected: "Hello...",
		},
		{
			name:     "empty text",
			text:     "",
			maxLen:   10,
			expected: "",
		},
		{
			name:     "zero max length",
			text:     "Hello",
			maxLen:   0,
			expected: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateText(tt.text, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncateText(%q, %d) = %q, want %q", tt.text, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func TestExtractServerVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard output",
			input:    "Client Version: v1.28.0\nServer Version: v1.27.5",
			expected: "Server Version: v1.27.5",
		},
		{
			name:     "only server version",
			input:    "Server Version: v1.28.0",
			expected: "Server Version: v1.28.0",
		},
		{
			name:     "JSON format with gitVersion",
			input:    `{"serverVersion": {"gitVersion": "v1.28.0"}}`,
			expected: `{"serverVersion": {"gitVersion": "v1.28.0"}}`,
		},
		{
			name:     "no server version",
			input:    "Client Version: v1.28.0",
			expected: "Client Version: v1.28.0",
		},
		{
			name:     "empty output",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    "   \n   ",
			expected: "   \n   ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractServerVersion(tt.input)
			if result != tt.expected {
				t.Errorf("extractServerVersion(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestConversationHistoryJSONMarshal(t *testing.T) {
	history := NewConversationHistory("test-cluster")
	history.AddEntry("Q1", "A1", "cluster")
	history.UpdateClusterStatus(&ClusterStatus{NodeCount: 3})

	data, err := json.Marshal(history)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	if !strings.Contains(string(data), "test-cluster") {
		t.Error("expected JSON to contain cluster name")
	}
	if !strings.Contains(string(data), "Q1") {
		t.Error("expected JSON to contain question")
	}
}

func TestConversationHistoryConcurrency(t *testing.T) {
	history := NewConversationHistory("test-cluster")

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			history.AddEntry("Question", "Answer", "cluster")
			_ = history.GetRecentContext(5)
			history.UpdateClusterStatus(&ClusterStatus{NodeCount: n})
			_ = history.GetClusterStatus()
			_ = history.GetClusterStatusContext()
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic and should have entries
	if len(history.Entries) < 1 {
		t.Error("expected at least 1 entry after concurrent operations")
	}
}

func TestGetRecentContextWithLongAnswers(t *testing.T) {
	history := NewConversationHistory("test-cluster")

	// Add entry with very long answer
	longAnswer := strings.Repeat("x", MaxAnswerLengthInContext+100)
	history.AddEntry("Question", longAnswer, "cluster")

	ctx := history.GetRecentContext(1)

	// Answer should be truncated
	if strings.Contains(ctx, strings.Repeat("x", MaxAnswerLengthInContext+100)) {
		t.Error("expected answer to be truncated in context")
	}
	if !strings.Contains(ctx, "...") {
		t.Error("expected truncated answer to have ellipsis")
	}
}

func TestClusterStatusZeroValues(t *testing.T) {
	status := ClusterStatus{
		Timestamp:      time.Time{},
		NodeCount:      0,
		PodCount:       0,
		NamespaceCount: 0,
		Version:        "",
		Context:        "",
	}

	if !status.Timestamp.IsZero() {
		t.Error("expected zero timestamp")
	}
	if status.NodeCount != 0 {
		t.Errorf("expected NodeCount 0, got %d", status.NodeCount)
	}
}
