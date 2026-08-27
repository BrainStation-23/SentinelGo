//go:build windows

package config

import (
	"encoding/base64"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiProtector protects credentials with the Windows Data Protection API.
//
// DPAPI is the OS-provided answer to exactly this problem, and using it keeps
// the promise that this agent ships no home-grown cryptography: the key
// derivation, algorithm choice and key storage are all the platform's.
//
// # Machine scope, deliberately
//
// CRYPTPROTECT_LOCAL_MACHINE binds the ciphertext to the machine rather than to
// a user profile. Both parts of that matter:
//
//   - It is REQUIRED for correctness here. The service runs as LocalSystem, but
//     config.json is also written by the installer and read by the elevated
//     CLI (-status, -telemetry-health) running as an administrator. User-scope
//     protection would bind the blob to whichever account happened to write it,
//     and the next reader would fail — including the service itself after a
//     ManagedServiceAccount or service-identity change.
//   - It matches the threat being addressed. The risk is credentials leaving
//     the endpoint in a backup, a disk image or a copied config directory;
//     machine scope makes all of those useless elsewhere.
//
// What it does not do is stop another local process from unprotecting the blob
// if it can read the file. That is what the file's DACL is for — SYSTEM and
// Administrators only — and the two controls are complementary: the DACL
// governs who on this machine may read it, DPAPI governs whether it means
// anything anywhere else.
//
// No additional entropy is passed. Entropy would have to be stored somewhere on
// the same machine to be usable by the agent, so it would add a step for an
// attacker who already has local access and nothing at all against the copied-
// file threat this defends.
type dpapiProtector struct{}

// cryptProtectLocalMachine is CRYPTPROTECT_LOCAL_MACHINE. x/sys/windows
// declares the CryptProtectData/CryptUnprotectData syscalls but not this flag.
const cryptProtectLocalMachine = 0x4

// dpapiDescription is stored inside the blob by DPAPI itself. It is metadata
// for anyone inspecting the blob and is never used as a key or as entropy.
const dpapiDescription = "SentinelGo agent credential"

func newProtector() protector { return dpapiProtector{} }

func (dpapiProtector) Name() string { return protectorDPAPI }

func (dpapiProtector) Protect(plaintext string) (string, error) {
	in := []byte(plaintext)

	desc, err := windows.UTF16PtrFromString(dpapiDescription)
	if err != nil {
		return "", fmt.Errorf("encode description: %w", err)
	}

	var out windows.DataBlob
	if err := windows.CryptProtectData(
		blobOf(in), desc, nil, 0, nil, cryptProtectLocalMachine, &out,
	); err != nil {
		return "", fmt.Errorf("CryptProtectData: %w", err)
	}
	defer freeBlob(&out)

	return base64.StdEncoding.EncodeToString(copyBlob(&out)), nil
}

func (dpapiProtector) Unprotect(body string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", fmt.Errorf("decode protected credential: %w", err)
	}

	var out windows.DataBlob
	// The description pointer is discarded: it is DPAPI's own metadata, not
	// something this code trusts or acts on.
	if err := windows.CryptUnprotectData(
		blobOf(raw), nil, nil, 0, nil, cryptProtectLocalMachine, &out,
	); err != nil {
		return "", fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer freeBlob(&out)

	return string(copyBlob(&out)), nil
}

// blobOf points a DATA_BLOB at b without copying it.
//
// An empty slice would leave Data nil, which DPAPI rejects with an unhelpful
// parameter error, so it is given a one-byte backing array with a zero length.
// Callers never protect an empty value (protectValue returns early), so this is
// defence against a future caller rather than a live path.
func blobOf(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		empty := [1]byte{}
		return &windows.DataBlob{Size: 0, Data: &empty[0]}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// copyBlob copies a DATA_BLOB's contents into Go-managed memory.
//
// The copy is what makes freeing the blob safe: the memory DPAPI returns is
// LocalAlloc'd and must be released with LocalFree, so nothing may retain a
// slice that still points into it.
func copyBlob(b *windows.DataBlob) []byte {
	if b.Data == nil || b.Size == 0 {
		return nil
	}
	out := make([]byte, b.Size)
	copy(out, unsafe.Slice(b.Data, b.Size))
	return out
}

// freeBlob releases the buffer DPAPI allocated, and zeroes it first.
//
// Zeroing matters on the unprotect path: that buffer holds the plaintext
// credential, and leaving it in freed heap memory is exactly the kind of
// residue a crash dump or a later allocation can expose.
func freeBlob(b *windows.DataBlob) {
	if b.Data == nil {
		return
	}
	if b.Size > 0 {
		buf := unsafe.Slice(b.Data, b.Size)
		for i := range buf {
			buf[i] = 0
		}
	}
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	b.Data = nil
	b.Size = 0
}
