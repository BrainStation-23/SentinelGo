package artifact_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"sentinelgo/internal/artifact"
)

// validSpec builds a Spec that passes Validate for the given content bytes.
func validSpec(id string, content []byte) artifact.Spec {
	h := sha256.Sum256(content)
	return artifact.Spec{
		ID:       id,
		Bucket:   "app-installers",
		Path:     "artifacts/abc/" + id + ".bin",
		Filename: id + ".bin",
		SHA256:   hex.EncodeToString(h[:]),
		Size:     int64(len(content)),
	}
}

// ── Validate ──────────────────────────────────────────────────────────────────

func TestValidate_Empty(t *testing.T) {
	if err := artifact.Validate(nil); err != nil {
		t.Errorf("Validate(nil) = %v, want nil", err)
	}
	if err := artifact.Validate([]artifact.Spec{}); err != nil {
		t.Errorf("Validate([]) = %v, want nil", err)
	}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := artifact.Validate([]artifact.Spec{validSpec("installer", []byte("binary data"))}); err != nil {
		t.Errorf("Validate(valid) = %v, want nil", err)
	}
}

func TestValidate_MaxArtifacts(t *testing.T) {
	specs := make([]artifact.Spec, 5)
	for i := range specs {
		specs[i] = validSpec(fmt.Sprintf("a%d", i), []byte("x"))
	}
	if err := artifact.Validate(specs); err != nil {
		t.Errorf("Validate(5 specs) = %v, want nil", err)
	}
}

func TestValidate_TooManyArtifacts(t *testing.T) {
	specs := make([]artifact.Spec, 6)
	for i := range specs {
		specs[i] = validSpec(fmt.Sprintf("a%d", i), []byte("x"))
	}
	if err := artifact.Validate(specs); err == nil {
		t.Error("expected error for 6 artifacts, got nil")
	}
}

func TestValidate_DuplicateID(t *testing.T) {
	sp := validSpec("installer", []byte("x"))
	if err := artifact.Validate([]artifact.Spec{sp, sp}); err == nil {
		t.Error("expected error for duplicate id, got nil")
	}
}

func TestValidate_InvalidID(t *testing.T) {
	bad := []string{
		"",
		"1starts_with_number",
		"HasUpper",
		"has-hyphen",
		strings.Repeat("a", 33), // too long (max 32 chars total)
	}
	for _, id := range bad {
		sp := validSpec("good", []byte("x"))
		sp.ID = id
		if err := artifact.Validate([]artifact.Spec{sp}); err == nil {
			t.Errorf("Validate with id=%q: expected error, got nil", id)
		}
	}
}

func TestValidate_InvalidBucket(t *testing.T) {
	sp := validSpec("installer", []byte("x"))
	sp.Bucket = "not-allowed"
	if err := artifact.Validate([]artifact.Spec{sp}); err == nil {
		t.Error("expected error for unlisted bucket, got nil")
	}
}

func TestValidate_PathLeadingSlash(t *testing.T) {
	sp := validSpec("installer", []byte("x"))
	sp.Path = "/artifacts/installer.bin"
	if err := artifact.Validate([]artifact.Spec{sp}); err == nil {
		t.Error("expected error for path with leading slash, got nil")
	}
}

func TestValidate_PathTraversal(t *testing.T) {
	sp := validSpec("installer", []byte("x"))
	sp.Path = "artifacts/../../../etc/passwd"
	if err := artifact.Validate([]artifact.Spec{sp}); err == nil {
		t.Error("expected error for path traversal, got nil")
	}
}

func TestValidate_BadFilename(t *testing.T) {
	bad := []string{
		"",
		"../evil.bin",
		"has/slash.bin",
		strings.Repeat("a", 129), // too long
	}
	for _, fn := range bad {
		sp := validSpec("installer", []byte("x"))
		sp.Filename = fn
		if err := artifact.Validate([]artifact.Spec{sp}); err == nil {
			t.Errorf("Validate with filename=%q: expected error, got nil", fn)
		}
	}
}

func TestValidate_BadSHA256(t *testing.T) {
	cases := []string{
		"not-hex",
		strings.Repeat("a", 63), // too short
		strings.ToUpper(validSpec("installer", []byte("x")).SHA256), // uppercase
	}
	for _, hash := range cases {
		sp := validSpec("installer", []byte("x"))
		sp.SHA256 = hash
		if err := artifact.Validate([]artifact.Spec{sp}); err == nil {
			t.Errorf("Validate with sha256=%q: expected error, got nil", hash)
		}
	}
}

func TestValidate_SizeZero(t *testing.T) {
	sp := validSpec("installer", []byte("x"))
	sp.Size = 0
	if err := artifact.Validate([]artifact.Spec{sp}); err == nil {
		t.Error("expected error for size=0, got nil")
	}
}

func TestValidate_SizeTooLarge(t *testing.T) {
	sp := validSpec("installer", []byte("x"))
	sp.Size = (4 << 30) + 1
	if err := artifact.Validate([]artifact.Spec{sp}); err == nil {
		t.Error("expected error for size > 4 GiB, got nil")
	}
}
