package encryption

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func captureStdout(f func()) string {
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = originalStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestPrintError(t *testing.T) {
	err := fmt.Errorf("sample error")
	want := fmt.Sprintf("\033[1mERROR:\033[0m %s: %v\n", "Test message", err)

	output := captureStdout(func() {
		PrintError("Test message", err)
	})

	if output != want {
		t.Errorf("got %q, wanted %q", output, want)
	}
}

func TestPrintInfo(t *testing.T) {
	want := fmt.Sprintf("\033[1m%s\033[0m: %s\n", "INFO", "Test message")

	output := captureStdout(func() {
		PrintInfo("Test message")
	})

	if output != want {
		t.Errorf("got %q, wanted %q", output, want)
	}
}
