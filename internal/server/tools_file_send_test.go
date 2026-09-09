package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeFileExportStoreOneShotAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	store := newRuntimeFileExportStore()
	store.now = func() time.Time { return now }
	file, err := os.CreateTemp(t.TempDir(), "export")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString("hello"); err != nil {
		t.Fatal(err)
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	token, expires, err := store.issue(runtimeFileExport{File: file, FileName: "hello.txt", MIMEType: "text/plain", Size: 5})
	if err != nil || len(token) != 48 || !expires.Equal(now.Add(runtimeFileExportTTL)) {
		t.Fatalf("issue token=%q expires=%v err=%v", token, expires, err)
	}
	if record, ok := store.take(token); !ok || record.FileName != "hello.txt" {
		t.Fatal("valid export token rejected")
	} else {
		_ = record.File.Close()
	}
	if _, ok := store.take(token); ok {
		t.Fatal("export token reused")
	}
	file2, _ := os.CreateTemp(t.TempDir(), "expired")
	token, _, err = store.issue(runtimeFileExport{File: file2, FileName: "expired.bin", Size: 0})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(runtimeFileExportTTL + time.Second)
	if _, ok := store.take(token); ok {
		t.Fatal("expired export token accepted")
	}
}

func TestRuntimePublicDeviceURL(t *testing.T) {
	accepted := map[string]string{
		"https://mcpmac.example.test/d/device":  "https://mcpmac.example.test/d/device",
		"https://mcpmac.example.test/d/device/": "https://mcpmac.example.test/d/device",
	}
	for raw, want := range accepted {
		got, err := runtimePublicDeviceURL(raw)
		if err != nil || got != want {
			t.Fatalf("%q -> %q %v", raw, got, err)
		}
	}
	for _, raw := range []string{"http://mcpmac.example.test/d/device", "https://user@mcpmac.example.test/d/device", "https://mcpmac.example.test/", "https://mcpmac.example.test/d/device?x=1"} {
		if _, err := runtimePublicDeviceURL(raw); err == nil {
			t.Fatalf("unsafe public URL accepted: %s", raw)
		}
	}
}

func TestFileTransferHTTPStreamsOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	body := bytes.Repeat([]byte("x"), 4096)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{fileExports: newRuntimeFileExportStore()}
	token, _, err := r.fileExports.issue(runtimeFileExport{File: file, FileName: "payload.bin", MIMEType: "application/octet-stream", Size: int64(len(body))})
	if err != nil {
		t.Fatal(err)
	}
	nextCalled := false
	handler := r.fileTransferHTTP(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { nextCalled = true; w.WriteHeader(204) }))
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/files/export/"+token, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), body) || nextCalled {
		t.Fatalf("export response code=%d len=%d next=%v", response.Code, response.Body.Len(), nextCalled)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Disposition") == "" {
		t.Fatal("download headers missing")
	}
	reused := httptest.NewRecorder()
	handler.ServeHTTP(reused, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/files/export/"+token, nil))
	if reused.Code != http.StatusNotFound {
		t.Fatalf("reused export status=%d", reused.Code)
	}
	passthrough := httptest.NewRecorder()
	handler.ServeHTTP(passthrough, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/mcp", nil))
	if passthrough.Code != http.StatusNoContent || !nextCalled {
		t.Fatal("non-export route did not pass through")
	}
}
