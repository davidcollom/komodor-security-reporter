package state

import "context"

// Backend is the storage contract for dedupe state.
type Backend interface {
	GetEntry(ctx context.Context, key string) (*Entry, error)
	SetEntry(ctx context.Context, key string, entry *Entry) error
	DeleteEntry(ctx context.Context, key string) error
}
