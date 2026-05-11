package state

import (
	"context"
	"errors"

	gocachestore "github.com/eko/gocache/lib/v4/store"
)

// Backend is the storage contract for dedupe state.
type Backend interface {
	GetEntry(ctx context.Context, key string) (*Entry, error)
	SetEntry(ctx context.Context, key string, entry *Entry) error
	DeleteEntry(ctx context.Context, key string) error
}

// IsCacheNotFound returns true when the error is a gocache not-found error.
func IsCacheNotFound(err error) bool {
	if err == nil {
		return false
	}

	var notFound *gocachestore.NotFound

	return errors.As(err, &notFound)
}
