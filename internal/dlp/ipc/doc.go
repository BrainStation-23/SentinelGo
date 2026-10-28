// Package ipc is the protocol between the service and the session helpers:
// length-prefixed JSON frames over a named pipe (Windows) or a Unix socket
// (macOS, Linux). The service takes the user identity in events from the
// peer's OS credentials, never from message fields.
//
// The transport is added in #262.
package ipc
