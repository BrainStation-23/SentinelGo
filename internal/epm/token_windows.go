//go:build windows

package epm

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// DuplicateAsPrimaryToken duplicates srcToken (typically the impersonation-
// level token returned by WTSQueryUserToken) into a new primary token
// suitable for CreateProcessAsUser. The caller must Close() the returned
// token.
func DuplicateAsPrimaryToken(srcToken windows.Token) (windows.Token, error) {
	var dup windows.Token
	err := windows.DuplicateTokenEx(
		srcToken,
		windows.TOKEN_ALL_ACCESS,
		nil, // default security attributes
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dup,
	)
	if err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	return dup, nil
}

// environmentBlock wraps the *uint16 CreateEnvironmentBlock/DestroyEnvironmentBlock
// pair so callers cannot forget to free it.
type environmentBlock struct {
	ptr *uint16
}

// BuildEnvironmentBlock creates the user environment block (HKCU-derived
// variables, per-user paths, etc.) for token, as required by
// CreateProcessAsUser. The caller must call Close() on the result.
func BuildEnvironmentBlock(token windows.Token) (*environmentBlock, error) {
	var block *uint16
	if err := windows.CreateEnvironmentBlock(&block, token, false); err != nil {
		return nil, fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	return &environmentBlock{ptr: block}, nil
}

// Close releases the environment block. Safe to call on a zero-value/already
// freed block.
func (b *environmentBlock) Close() error {
	if b == nil || b.ptr == nil {
		return nil
	}
	err := windows.DestroyEnvironmentBlock(b.ptr)
	b.ptr = nil
	if err != nil {
		return fmt.Errorf("DestroyEnvironmentBlock: %w", err)
	}
	return nil
}
