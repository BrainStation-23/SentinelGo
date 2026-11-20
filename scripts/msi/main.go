// msi holds the release pipeline's facts about the generic Windows MSI (#358)
// and macOS package (#352) that must stay the same from one release to the
// next, so they live in code and in one place.
//
// Modes:
//
//	go run ./scripts/msi -version v4.1.0 [-flavor readonly] -vars
//	    print MSI_VERSION, PRODUCT_CODE, UPGRADE_CODE and PRODUCT_NAME as
//	    KEY=value lines (for $GITHUB_ENV), passed to `wix build -d`
//	go run ./scripts/msi -version v4.1.0 -manifest dist/sentinelgo-installers.json \
//	        -msi dist/sentinelgo-windows-amd64.msi [-msi dist/sentinelgo-readonly-windows-amd64.msi] \
//	        [-pkg dist/sentinelgo-darwin-universal.pkg] [-pkg dist/sentinelgo-readonly-darwin-universal.pkg]
//	    write the installers metadata the backend mirror reads
//	    (Compliance-OS#555, flavors Compliance-OS#1082): each installer's
//	    name, ProductCode or package identifier, and SHA-256. Each file's
//	    flavor comes from its name. The full MSI is required. A -pkg is given
//	    only for a signed macOS package: MDM can't install an unsigned one.
//
// The UpgradeCode never changes: it is what makes each new MSI upgrade the
// one installed. Every flavor's MSI shares it (#550), so installing one
// flavor replaces the other. The ProductCode is new for every version (a
// major upgrade) and differs per flavor, but is the same for any rebuild of
// that version and flavor, because it is derived from them: an MDM installs
// by ProductCode (…/MSI/{ProductCode}/DownloadInstall), so the backend must
// be able to rely on it.
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
	"slices"
	"strconv"
	"strings"
)

// UpgradeCode identifies the SentinelGo agent MSI across all versions and
// flavors. Never change it: MSIs with another UpgradeCode don't upgrade each
// other.
const UpgradeCode = "{80615706-0C1E-43A0-8101-8F2B18A05C7B}"

// The agent builds (#547): the slugs of Compliance-OS's agent_flavors.
// FlavorFull is the build the manifest's top-level msi and pkg describe.
const (
	FlavorFull     = "full"
	FlavorReadOnly = "readonly"
)

// flavors are the builds that have packages.
var flavors = []string{FlavorFull, FlavorReadOnly}

// assetPrefix is the flavor's release asset prefix (agent_flavors.asset_prefix).
func assetPrefix(flavor string) string {
	if flavor == FlavorFull {
		return "sentinelgo-"
	}
	return "sentinelgo-" + flavor + "-"
}

// msiName and pkgName are the release asset names of a flavor's MSI and
// generic macOS package.
func msiName(flavor string) string { return assetPrefix(flavor) + "windows-amd64.msi" }
func pkgName(flavor string) string { return assetPrefix(flavor) + "darwin-universal.pkg" }

// PkgIdentifier is the package identifier (the receipt MDM checks) of every
// flavor's package: one product, so installing one flavor replaces the
// other. It never changes; Compliance-OS (installer-packages/pkg.ts,
// installer-metadata.ts) uses the same one.
const PkgIdentifier = "com.sentinelgo.agent"

// productName is the MSI's ProductName, shown in Installed apps.
func productName(flavor string) string {
	if flavor == FlavorFull {
		return "SentinelGo Agent"
	}
	return "SentinelGo Agent (" + flavor + ")"
}

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

// productCode is the ProductCode of a version and flavor: an RFC 4122
// version 5 UUID in the UpgradeCode's namespace, of the MSI version for the
// full build (as before flavors, so its codes never change) and of
// "<version>/<flavor>" for the others.
func productCode(version, flavor string) string {
	name := version
	if flavor != FlavorFull {
		name += "/" + flavor
	}
	ns, err := hex.DecodeString(strings.ReplaceAll(strings.Trim(UpgradeCode, "{}"), "-", ""))
	if err != nil || len(ns) != 16 {
		panic("bad UpgradeCode")
	}
	h := sha1.New() // #nosec G401 -- see the import
	h.Write(ns)
	h.Write([]byte(name))
	u := h.Sum(nil)[:16]
	u[6] = u[6]&0x0f | 0x50 // version 5
	u[8] = u[8]&0x3f | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(u)
	return strings.ToUpper(fmt.Sprintf("{%s-%s-%s-%s-%s}", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32]))
}

// Installers is sentinelgo-installers.json (contract: Compliance-OS#1082).
// MSI and Pkg are the full build's, as before flavors. Flavors lists every
// flavor's packages by slug, the full build's again among them. A pkg is
// there only when the release has a signed one.
type Installers struct {
	Version string                  `json:"version"`
	MSI     InstallerInfo           `json:"msi"`
	Pkg     *PkgInfo                `json:"pkg,omitempty"`
	Flavors map[string]FlavorAssets `json:"flavors"`
}

// FlavorAssets are one flavor's packages.
type FlavorAssets struct {
	MSI *InstallerInfo `json:"msi,omitempty"`
	Pkg *PkgInfo       `json:"pkg,omitempty"`
}

// PkgInfo describes a macOS package.
type PkgInfo struct {
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
	SHA256     string `json:"sha256"`
}

// InstallerInfo describes an MSI.
type InstallerInfo struct {
	Name        string `json:"name"`
	ProductCode string `json:"product_code"`
	SHA256      string `json:"sha256"`
}

// fileSHA256 is the hex SHA-256 of the file at path.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- release tooling, path from argv
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// flavorOf is the flavor whose asset name, name(flavor), is base.
func flavorOf(base string, name func(string) string) (string, bool) {
	for _, f := range flavors {
		if name(f) == base {
			return f, true
		}
	}
	return "", false
}

func manifest(tag string, msiPaths, pkgPaths []string) ([]byte, error) {
	v, err := msiVersion(tag)
	if err != nil {
		return nil, err
	}
	m := Installers{Version: tag, Flavors: map[string]FlavorAssets{}}
	for _, p := range msiPaths {
		f, ok := flavorOf(filepath.Base(p), msiName)
		if !ok {
			return nil, fmt.Errorf("%s: an MSI must be named %s or %s", p, msiName(FlavorFull), msiName("<flavor>"))
		}
		a := m.Flavors[f]
		if a.MSI != nil {
			return nil, fmt.Errorf("%s: the %s MSI is given twice", p, f)
		}
		sum, err := fileSHA256(p)
		if err != nil {
			return nil, err
		}
		a.MSI = &InstallerInfo{Name: msiName(f), ProductCode: productCode(v, f), SHA256: sum}
		m.Flavors[f] = a
	}
	for _, p := range pkgPaths {
		f, ok := flavorOf(filepath.Base(p), pkgName)
		if !ok {
			return nil, fmt.Errorf("%s: a package must be named %s or %s", p, pkgName(FlavorFull), pkgName("<flavor>"))
		}
		a := m.Flavors[f]
		if a.Pkg != nil {
			return nil, fmt.Errorf("%s: the %s package is given twice", p, f)
		}
		sum, err := fileSHA256(p)
		if err != nil {
			return nil, err
		}
		a.Pkg = &PkgInfo{Name: pkgName(f), Identifier: PkgIdentifier, SHA256: sum}
		m.Flavors[f] = a
	}
	full := m.Flavors[FlavorFull]
	if full.MSI == nil {
		return nil, fmt.Errorf("the full build's MSI (%s) is required", msiName(FlavorFull))
	}
	m.MSI, m.Pkg = *full.MSI, full.Pkg
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// paths is a flag that can be given more than once.
type paths []string

func (p *paths) String() string     { return strings.Join(*p, ",") }
func (p *paths) Set(v string) error { *p = append(*p, v); return nil }

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("msi", flag.ContinueOnError)
	tag := fs.String("version", "", "the release tag, vMAJOR.MINOR.PATCH")
	flavor := fs.String("flavor", FlavorFull, "the build, with -vars: "+strings.Join(flavors, " or "))
	vars := fs.Bool("vars", false, "print MSI_VERSION, PRODUCT_CODE, UPGRADE_CODE and PRODUCT_NAME")
	out := fs.String("manifest", "", "write sentinelgo-installers.json here")
	var msiPaths, pkgPaths paths
	fs.Var(&msiPaths, "msi", "a built MSI, with -manifest (once per flavor)")
	fs.Var(&pkgPaths, "pkg", "a signed macOS package, with -manifest (once per flavor)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *vars:
		if !slices.Contains(flavors, *flavor) {
			return fmt.Errorf("unknown flavor %q (want %s)", *flavor, strings.Join(flavors, " or "))
		}
		v, err := msiVersion(*tag)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "MSI_VERSION=%s\nPRODUCT_CODE=%s\nUPGRADE_CODE=%s\nPRODUCT_NAME=%s\n",
			v, productCode(v, *flavor), UpgradeCode, productName(*flavor))
		return err
	case *out != "" && len(msiPaths) > 0:
		b, err := manifest(*tag, msiPaths, pkgPaths)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, b, 0o644) // #nosec G306 -- a public release asset
	default:
		return errors.New("usage: msi -version vX.Y.Z ([-flavor F] -vars | -manifest OUT -msi MSI... [-pkg PKG...])")
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "msi:", err)
		os.Exit(1)
	}
}
