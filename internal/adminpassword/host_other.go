//go:build !windows

package adminpassword

import "errors"

var errNotWindows = errors.New("local admin password rotation is Windows only")

type otherHost struct{}

// NewHost returns the platform host. Rotation is Windows only (#361); here
// every device reports unsupported.
func NewHost() Host { return otherHost{} }

func (otherHost) Unsupported() string                      { return "os" }
func (otherHost) ManagedBy() (string, error)               { return "", nil }
func (otherHost) Account(string) (AccountInfo, error)      { return AccountInfo{}, errNotWindows }
func (otherHost) AccountBySID(string) (AccountInfo, error) { return AccountInfo{}, errNotWindows }
func (otherHost) SetPassword(AccountInfo, []byte) error    { return errNotWindows }
