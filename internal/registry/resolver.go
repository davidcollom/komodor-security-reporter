package registry

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/sirupsen/logrus"
)

// Resolver resolves mutable image tags to immutable digests.
type Resolver struct {
	log logrus.FieldLogger
}

// NewResolver creates a new image digest resolver.
func NewResolver(log logrus.FieldLogger) *Resolver {
	return &Resolver{
		log: log,
	}
}

// Resolve resolves an image reference to a digest where possible.
// If the reference is already a digest, it is returned unchanged.
// If resolution fails, the original reference is returned with an error logged.
func (r *Resolver) Resolve(ctx context.Context, imageRef *ImageRef) (*ImageRef, error) {
	// If already a digest, return as-is
	if imageRef.Digest != "" {
		return imageRef, nil
	}

	// Attempt to resolve tag to digest
	digest, err := crane.Digest(imageRef.Resolved, crane.WithContext(ctx))
	if err != nil {
		// Log but don't fail - proceed with unresolved reference
		r.log.WithFields(logrus.Fields{
			"image": imageRef.Original,
			"error": err.Error(),
		}).Warn("failed to resolve image digest")

		return imageRef, fmt.Errorf("resolve digest: %w", err)
	}

	// Create resolved reference with digest
	resolved := &ImageRef{
		Original:   imageRef.Original,
		Registry:   imageRef.Registry,
		Repository: imageRef.Repository,
		Tag:        imageRef.Tag,
		Digest:     digest,
		Resolved:   fmt.Sprintf("%s/%s@%s", imageRef.Registry, imageRef.Repository, digest),
	}

	return resolved, nil
}
