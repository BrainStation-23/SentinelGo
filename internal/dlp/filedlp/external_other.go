//go:build !linux && !windows && !darwin

package filedlp

func externalMounts() []Destination { return nil }
