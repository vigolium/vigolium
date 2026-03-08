package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	acp "github.com/coder/acp-go-sdk"
)

func TestACPClient_CollectedOutput(t *testing.T) {
	client := newACPClient()

	// Simulate multiple message chunks
	chunks := []string{"Hello, ", "world! ", "This is a test."}
	ctx := context.Background()
	for _, chunk := range chunks {
		err := client.SessionUpdate(ctx, acp.SessionNotification{
			Update: acp.UpdateAgentMessageText(chunk),
		})
		if err != nil {
			t.Fatalf("SessionUpdate() error = %v", err)
		}
	}

	got := client.collectedOutput()
	want := "Hello, world! This is a test."
	if got != want {
		t.Errorf("collectedOutput() = %q, want %q", got, want)
	}
}

func TestACPClient_EmptyOutput(t *testing.T) {
	client := newACPClient()
	if got := client.collectedOutput(); got != "" {
		t.Errorf("collectedOutput() = %q, want empty", got)
	}
}

func TestACPClient_SessionUpdate_ToolCall(t *testing.T) {
	client := newACPClient()
	ctx := context.Background()

	// ToolCall updates should not affect collected output
	err := client.SessionUpdate(ctx, acp.SessionNotification{
		Update: acp.StartToolCall("tc-1", "Read file"),
	})
	if err != nil {
		t.Fatalf("SessionUpdate() error = %v", err)
	}

	if got := client.collectedOutput(); got != "" {
		t.Errorf("collectedOutput() after tool call = %q, want empty", got)
	}
}

func TestACPClient_RequestPermission_AllowOnce(t *testing.T) {
	client := newACPClient()
	ctx := context.Background()

	resp, err := client.RequestPermission(ctx, acp.RequestPermissionRequest{
		Options: []acp.PermissionOption{
			{OptionId: "reject", Name: "Deny", Kind: acp.PermissionOptionKindRejectOnce},
			{OptionId: "allow", Name: "Allow", Kind: acp.PermissionOptionKindAllowOnce},
			{OptionId: "always", Name: "Always", Kind: acp.PermissionOptionKindAllowAlways},
		},
	})
	if err != nil {
		t.Fatalf("RequestPermission() error = %v", err)
	}

	// Should prefer allow_once
	if resp.Outcome.Selected == nil {
		t.Fatal("expected Selected outcome")
	}
	if resp.Outcome.Selected.OptionId != "allow" {
		t.Errorf("selected option = %q, want %q", resp.Outcome.Selected.OptionId, "allow")
	}
}

func TestACPClient_RequestPermission_AllowAlways(t *testing.T) {
	client := newACPClient()
	ctx := context.Background()

	resp, err := client.RequestPermission(ctx, acp.RequestPermissionRequest{
		Options: []acp.PermissionOption{
			{OptionId: "reject", Name: "Deny", Kind: acp.PermissionOptionKindRejectOnce},
			{OptionId: "always", Name: "Always", Kind: acp.PermissionOptionKindAllowAlways},
		},
	})
	if err != nil {
		t.Fatalf("RequestPermission() error = %v", err)
	}

	// No allow_once → should fall through to allow_always
	if resp.Outcome.Selected == nil {
		t.Fatal("expected Selected outcome")
	}
	if resp.Outcome.Selected.OptionId != "always" {
		t.Errorf("selected option = %q, want %q", resp.Outcome.Selected.OptionId, "always")
	}
}

func TestACPClient_RequestPermission_NoOptions(t *testing.T) {
	client := newACPClient()
	ctx := context.Background()

	resp, err := client.RequestPermission(ctx, acp.RequestPermissionRequest{
		Options: nil,
	})
	if err != nil {
		t.Fatalf("RequestPermission() error = %v", err)
	}

	if resp.Outcome.Cancelled == nil {
		t.Error("expected Cancelled outcome when no options available")
	}
}

func TestACPClient_ReadTextFile_Allowed(t *testing.T) {
	// Create a temp directory with a file
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(testFile, []byte("file content"), 0644); err != nil {
		t.Fatal(err)
	}

	client := newACPClient(withAllowedPaths(dir))
	ctx := context.Background()

	resp, err := client.ReadTextFile(ctx, acp.ReadTextFileRequest{Path: testFile})
	if err != nil {
		t.Fatalf("ReadTextFile() error = %v", err)
	}
	if resp.Content != "file content" {
		t.Errorf("ReadTextFile() content = %q, want %q", resp.Content, "file content")
	}
}

func TestACPClient_ReadTextFile_OutsideAllowed(t *testing.T) {
	dir := t.TempDir()
	otherDir := t.TempDir()
	testFile := filepath.Join(otherDir, "secret.txt")
	if err := os.WriteFile(testFile, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	client := newACPClient(withAllowedPaths(dir))
	ctx := context.Background()

	_, err := client.ReadTextFile(ctx, acp.ReadTextFileRequest{Path: testFile})
	if err == nil {
		t.Error("ReadTextFile() should return error for path outside allowed directories")
	}
}

func TestACPClient_ReadTextFile_NoRestrictions(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	// No allowed paths → all paths allowed
	client := newACPClient()
	ctx := context.Background()

	resp, err := client.ReadTextFile(ctx, acp.ReadTextFileRequest{Path: testFile})
	if err != nil {
		t.Fatalf("ReadTextFile() error = %v", err)
	}
	if resp.Content != "content" {
		t.Errorf("ReadTextFile() content = %q, want %q", resp.Content, "content")
	}
}

func TestACPClient_StreamWriter(t *testing.T) {
	var buf bytes.Buffer
	client := newACPClient(withStreamWriter(&buf))
	ctx := context.Background()

	chunks := []string{"Hello, ", "streamed ", "world!"}
	for _, chunk := range chunks {
		err := client.SessionUpdate(ctx, acp.SessionNotification{
			Update: acp.UpdateAgentMessageText(chunk),
		})
		if err != nil {
			t.Fatalf("SessionUpdate() error = %v", err)
		}
	}

	// Stream writer should have received all chunks
	want := "Hello, streamed world!"
	if got := buf.String(); got != want {
		t.Errorf("stream writer got %q, want %q", got, want)
	}

	// Collected output should also match
	if got := client.collectedOutput(); got != want {
		t.Errorf("collectedOutput() = %q, want %q", got, want)
	}
}

func TestACPClient_NilStreamWriter(t *testing.T) {
	// Ensure nil stream writer doesn't panic
	client := newACPClient()
	ctx := context.Background()

	err := client.SessionUpdate(ctx, acp.SessionNotification{
		Update: acp.UpdateAgentMessageText("test"),
	})
	if err != nil {
		t.Fatalf("SessionUpdate() error = %v", err)
	}

	if got := client.collectedOutput(); got != "test" {
		t.Errorf("collectedOutput() = %q, want %q", got, "test")
	}
}

func TestACPClient_WriteTextFile_Denied(t *testing.T) {
	client := newACPClient()
	ctx := context.Background()

	_, err := client.WriteTextFile(ctx, acp.WriteTextFileRequest{
		Path:    "/tmp/test.txt",
		Content: "data",
	})
	if err == nil {
		t.Error("WriteTextFile() should return error in scanner mode")
	}
}

func TestACPClient_Terminal_NoOps(t *testing.T) {
	client := newACPClient()
	ctx := context.Background()

	createResp, err := client.CreateTerminal(ctx, acp.CreateTerminalRequest{Command: "echo"})
	if err != nil {
		t.Errorf("CreateTerminal() unexpected error: %v", err)
	}
	if createResp.TerminalId == "" {
		t.Error("CreateTerminal() should return a stub terminal ID")
	}

	_, err = client.KillTerminalCommand(ctx, acp.KillTerminalCommandRequest{})
	if err != nil {
		t.Errorf("KillTerminalCommand() unexpected error: %v", err)
	}

	_, err = client.ReleaseTerminal(ctx, acp.ReleaseTerminalRequest{})
	if err != nil {
		t.Errorf("ReleaseTerminal() unexpected error: %v", err)
	}

	outputResp, err := client.TerminalOutput(ctx, acp.TerminalOutputRequest{})
	if err != nil {
		t.Errorf("TerminalOutput() unexpected error: %v", err)
	}
	if outputResp.Truncated {
		t.Error("TerminalOutput() should not be truncated")
	}

	exitResp, err := client.WaitForTerminalExit(ctx, acp.WaitForTerminalExitRequest{})
	if err != nil {
		t.Errorf("WaitForTerminalExit() unexpected error: %v", err)
	}
	if exitResp.ExitCode == nil || *exitResp.ExitCode != 0 {
		t.Error("WaitForTerminalExit() should return exit code 0")
	}
}
