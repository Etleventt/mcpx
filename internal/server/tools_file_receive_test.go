package server

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseChatFileInput(t *testing.T) {
	got, err := parseChatFileInput(map[string]any{
		"download_url": "https://mcpmac.example.test/d/device/files/token",
		"file_id":      "file_123",
		"mime_type":    "image/png",
		"file_name":    "screen.png",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.FileID != "file_123" || got.FileName != "screen.png" || got.MIMEType != "image/png" {
		t.Fatalf("unexpected parsed file: %+v", got)
	}
	for name, value := range map[string]any{
		"missing": map[string]any{"download_url": "https://mcpmac.example.test/d/device/files/token"},
		"wrong":   "not-an-object",
		"empty":   map[string]any{"download_url": "", "file_id": "file_123"},
	} {
		if _, err := parseChatFileInput(value); err == nil {
			t.Fatalf("invalid %s file input accepted", name)
		}
	}
}

func TestValidateRelayFileURLIsDeviceScoped(t *testing.T) {
	base := "https://mcpmac.example.test/d/device-1"
	accepted := []string{
		"https://mcpmac.example.test/d/device-1/files/token",
		"https://MCPMAC.example.test/d/device-1/files/another",
	}
	for _, raw := range accepted {
		if err := validateRelayFileURL(raw, base); err != nil {
			t.Fatalf("valid relay URL %q rejected: %v", raw, err)
		}
	}
	rejected := []string{
		"http://mcpmac.example.test/d/device-1/files/token",
		"https://other.example.test/d/device-1/files/token",
		"https://mcpmac.example.test/d/device-2/files/token",
		"https://mcpmac.example.test/d/device-1/mcp",
		"https://mcpmac.example.test/d/device-1/files/token?sig=unexpected",
		"https://user@mcpmac.example.test/d/device-1/files/token",
	}
	for _, raw := range rejected {
		if err := validateRelayFileURL(raw, base); err == nil {
			t.Fatalf("unsafe relay URL %q accepted", raw)
		}
	}
}

func TestReceiveTempNameStaysInDestinationDirectory(t *testing.T) {
	for _, parent := range []string{".", "inbox", filepath.Join("nested", "files")} {
		name, err := receiveTempName(parent)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(filepath.Base(name), ".subdesk-receive-") {
			t.Fatalf("unexpected temp name %q", name)
		}
		if parent == "." {
			if filepath.Dir(name) != "." {
				t.Fatalf("root temp escaped: %q", name)
			}
		} else if filepath.Dir(name) != parent {
			t.Fatalf("temp path %q escaped parent %q", name, parent)
		}
	}
}
