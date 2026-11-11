// msi holds the release pipeline's facts about the generic Windows MSI (#358)
// that must stay the same from one release to the next, so they live in code
// and in one place.
//
// Modes:
//
//	go run ./scripts/msi -version v4.1.0 -vars
//	    print MSI_VERSION, PRODUCT_CODE and UPGRADE_CODE as KEY=value lines
//	    (for $GITHUB_ENV), passed to `wix build -d`
//	go run ./scripts/msi -version v4.1.0 -manifest dist/sentinelgo-installers.json -msi dist/sentinelgo-windows-amd64.msi
//	    write the installers metadata the backend mirror reads
//	    (Compliance-OS#555): each installer's name, ProductCode and SHA-256
//
// The UpgradeCode never changes: it is what makes each new MSI upgrade the
// one installed. The ProductCode is new for every version (a major upgrade)
// but the same for any rebuild of that version, because it is derived from
// the version: an MDM installs by ProductCode (…/MSI/{ProductCode}/DownloadInstall),
// so the backend must be able to rely on it.
package main

import (
	"crypto/sha1" // #nosec G505 -- RFC 4122 name-based UUID (v5), not a security use
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// UpgradeCode identifies the SentinelGo agent MSI across all versions. Never
// change it: MSIs with another UpgradeCode don't upgrade each other.
const UpgradeCode = "{80615706-0C1E-43A0-8101-8F2B18A05C7B}"

// MSIName is the release asset name of the MSI.
const MSIName = "sentinelgo-windows-amd64.msi"

var tagRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// msiVersion turns a release tag into a ProductVersion. Windows Installer
// compares only major.minor.build, with limits of 255, 255 and 65535, so a
// tag outside them can't be told apart from another and is refused.
func msiVersion(tag string) (string, error) {
	m := tagRe.FindStringSubmatch(tag)
	if m == nil {
		return "", fmt.Errorf("%q is not a vMAJOR.MINOR.PATCH release tag", tag)
	}
	limits := []int{255, 255, 65535}
	for i, s := range m[1:] {
		n, err := strconv.Atoi(s)
		if err != nil || n > limits[i] {
			return "", fmt.Errorf("%q: part %d is above the MSI limit of %d", tag, i+1, limits[i])
		}
	}
	return strings.Join(m[1:], "."), nil
}

// productCode is the version's ProductCode: an RFC 4122 version 5 UUID of
// the MSI version in the UpgradeCode's namespace.
func productCode(version string) string {
	ns, err := hex.DecodeString(strings.ReplaceAll(strings.Trim(UpgradeCode, "{}"), "-", ""))
	if err != nil || len(ns) != 16 {
		panic("bad UpgradeCode")
	}
	h := sha1.New() // #nosec G401 -- see the import
	h.Write(ns)
	h.Write([]byte(version))
	u := h.Sum(nil)[:16]
	u[6] = u[6]&0x0f | 0x50 // version 5
	u[8] = u[8]&0x3f | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(u)
	return strings.ToUpper(fmt.Sprintf("{%s-%s-%s-%s-%s}", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32]))
}

// Installers is sentinelgo-installers.json. Pkg (macOS, #352) is added when
// that package exists.
type Installers struct {
	Version string        `json:"version"`
	MSI     InstallerInfo `json:"msi"`
}

// InstallerInfo describes one installer asset.
type InstallerInfo struct {
	Name        string `json:"name"`
	ProductCode string `json:"product_code"`
	SHA256      string `json:"sha256"`
}

func manifest(tag, msiPath string) ([]byte, error) {
	v, err := msiVersion(tag)
	if err != nil {
		return nil, err
	}
	if filepath.Base(msiPath) != MSIName {
		return nil, fmt.Errorf("%s: the MSI must be named %s", msiPath, MSIName)
	}
	f, err := os.Open(msiPath) // #nosec G304 -- release tooling, path from argv
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(Installers{Version: tag, MSI: InstallerInfo{
		Name: MSIName, ProductCode: productCode(v), SHA256: hex.EncodeToString(h.Sum(nil)),
	}}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("msi", flag.ContinueOnError)
	tag := fs.String("version", "", "the release tag, vMAJOR.MINOR.PATCH")
	vars := fs.Bool("vars", false, "print MSI_VERSION, PRODUCT_CODE and UPGRADE_CODE")
	out := fs.String("manifest", "", "write sentinelgo-installers.json here")
	msiPath := fs.String("msi", "", "the built MSI (with -manifest)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *vars:
		v, err := msiVersion(*tag)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "MSI_VERSION=%s\nPRODUCT_CODE=%s\nUPGRADE_CODE=%s\n", v, productCode(v), UpgradeCode)
		return err
	case *out != "" && *msiPath != "":
		b, err := manifest(*tag, *msiPath)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, b, 0o644) // #nosec G306 -- a public release asset
	default:
		return errors.New("usage: msi -version vX.Y.Z (-vars | -manifest OUT -msi MSI)")
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "msi:", err)
		os.Exit(1)
	}
}
