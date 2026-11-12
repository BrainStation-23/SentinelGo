//go:build !windows && !darwin && !linux

package watch

func start([]string, Handler) (Watcher, error) { return nil, ErrUnsupported }
