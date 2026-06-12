package task

import (
	"context"
	"log"

	"sentinelgo/internal/service/task/native"
	"sentinelgo/internal/taskstore"
)

// NativeTaskHandler handles a task entirely in Go — no script download required.
type NativeTaskHandler func(ctx context.Context, task taskstore.Task) (string, error)

// registerNativeHandlers builds the slug→handler map from the native sub-package registry.
// To add a new native task: create a file in native/, implement Handler, call Register()
// from init(). No changes here or anywhere else are required.
// Handlers may also implement native.PostRunner to declare slugs that run automatically
// after a successful execution.
func (s *TaskExecutorService) registerNativeHandlers() {
	s.nativeHandlers = make(map[string]NativeTaskHandler)
	for _, h := range native.Registry() {
		h := h
		for _, slug := range h.Slugs() {
			slug := slug
			s.nativeHandlers[slug] = func(ctx context.Context, task taskstore.Task) (string, error) {
				return s.runWithPostHooks(ctx, h, slug, task)
			}
		}
	}
}

func (s *TaskExecutorService) runWithPostHooks(ctx context.Context, h native.Handler, slug string, task taskstore.Task) (string, error) {
	note, err := h.Run(ctx, s.cfg, task)
	if err != nil {
		return note, err
	}
	pr, ok := h.(native.PostRunner)
	if !ok {
		return note, nil
	}
	for _, postSlug := range pr.PostRun() {
		ph := native.Find(postSlug)
		if ph == nil {
			log.Printf("post-run: no handler registered for slug %q (requested by %q)", postSlug, slug)
			continue
		}
		postNote, postErr := ph.Run(ctx, s.cfg, task)
		if postErr != nil {
			log.Printf("post-run %q (after %q) failed: %v", postSlug, slug, postErr)
		} else if postNote != "" {
			note += "; " + postNote
		}
	}
	return note, nil
}
