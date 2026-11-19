package uploadproxy

import (
	"errors"
	"fmt"
)

// RemoveLeftovers undoes what upload inspection may have left on the
// machine after an abrupt exit: the system proxy setting (macOS, Windows;
// Linux desktops' are the helpers'), the direct block (nftables, WFP) and the
// inspection CA. NewService does this when it starts; a build without
// upload inspection (the read-only build, #547) calls it at startup instead,
// so a device switched from the full build isn't left with redirects to a
// proxy that no longer runs. configDir is the directory of config.json.
func RemoveLeftovers(configDir string) error {
	var errs []error
	if err := NewRedirector(configDir).Remove(); err != nil {
		errs = append(errs, fmt.Errorf("upload redirect: %w", err))
	}
	if err := RemoveDirectBlock(); err != nil {
		errs = append(errs, fmt.Errorf("direct block: %w", err))
	}
	if err := NewTruster().Untrust(); err != nil {
		errs = append(errs, fmt.Errorf("inspection CA: %w", err))
	}
	return errors.Join(errs...)
}
