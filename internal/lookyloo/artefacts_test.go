package lookyloo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAtomicallyEnforcesTheLimitAndLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	if _, err := writeAtomically(dir, "x.zip", strings.NewReader("PK\x03\x04 too long"), 4); err == nil {
		t.Fatal("an oversized artefact was accepted")
	}
	if files, _ := os.ReadDir(dir); len(files) != 0 {
		t.Errorf("left behind: %v", files)
	}
}

func TestWriteAtomicallyHashesTheWholeFile(t *testing.T) {
	dir := t.TempDir()
	a, err := writeAtomically(dir, "x.bin", strings.NewReader("abc"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || a.Size != 3 || a.Path != filepath.Join(dir, "x.bin") {
		t.Errorf("artefact = %+v", a)
	}
}

func TestSaveFileNeedsADirectory(t *testing.T) {
	if _, err := SaveFile(" ", "x.png", []byte("x")); !errors.Is(err, ErrNoOutDir) {
		t.Errorf("err = %v", err)
	}
}
