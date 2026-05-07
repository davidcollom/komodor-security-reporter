package registry

import (
	"fmt"
	"strings"
)

// ImageRef represents a parsed container image reference.
type ImageRef struct {
	Original   string
	Registry   string
	Repository string
	Tag        string
	Digest     string
	Resolved   string
}

// Parse parses a container image reference string.
func Parse(imageStr string) (*ImageRef, error) {
	if imageStr == "" {
		return nil, fmt.Errorf("empty image reference")
	}

	ref := &ImageRef{Original: imageStr}
	imagePart := splitDigest(imageStr, ref)
	applyRegistryAndRepository(imagePart, ref)
	ref.Resolved = buildResolved(imagePart, ref)

	return ref, nil
}

func splitDigest(imageStr string, ref *ImageRef) string {
	imagePart := imageStr
	if idx := strings.Index(imageStr, "@"); idx > -1 {
		imagePart = imageStr[:idx]
		ref.Digest = imageStr[idx+1:]
	}

	return imagePart
}

func applyRegistryAndRepository(imagePart string, ref *ImageRef) {
	slashIdx := strings.Index(imagePart, "/")
	if slashIdx == -1 {
		ref.Registry = "docker.io"
		repo, tag := parseRepositoryTag(imagePart)
		ref.Repository = "library/" + repo
		assignDefaultTagIfNeeded(ref, tag)

		return
	}

	beforeSlash := imagePart[:slashIdx]
	afterSlash := imagePart[slashIdx+1:]

	if isRegistryHost(beforeSlash) {
		ref.Registry = beforeSlash
		repo, tag := parseRepositoryTag(afterSlash)
		ref.Repository = repo
		assignDefaultTagIfNeeded(ref, tag)

		return
	}

	ref.Registry = "docker.io"
	repo, tag := parseRepositoryTag(imagePart)
	ref.Repository = repo
	assignDefaultTagIfNeeded(ref, tag)
}

func parseRepositoryTag(value string) (string, string) {
	if idx := strings.Index(value, ":"); idx > -1 {
		parts := strings.SplitN(value, ":", 2)
		return parts[0], parts[1]
	}

	return value, ""
}

func assignDefaultTagIfNeeded(ref *ImageRef, tag string) {
	if tag != "" {
		ref.Tag = tag
		return
	}

	if ref.Digest == "" {
		ref.Tag = "latest"
	}
}

func buildResolved(imagePart string, ref *ImageRef) string {
	if ref.Digest != "" {
		return fmt.Sprintf("%s@%s", imagePart, ref.Digest)
	}

	if ref.Tag == "latest" && !strings.Contains(imagePart, ":") {
		return imagePart + ":latest"
	}

	return imagePart
}

func isRegistryHost(value string) bool {
	return strings.Contains(value, ".") || strings.Contains(value, ":") || value == "localhost"
}
