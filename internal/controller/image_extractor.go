package controller

import (
	corev1 "k8s.io/api/core/v1"
)

// ExtractedImage represents an image extracted from a workload.
type ExtractedImage struct {
	Image         string
	ContainerName string
}

// ImageExtractor extracts container images from Pod templates.
type ImageExtractor struct{}

// NewImageExtractor creates a new image extractor.
func NewImageExtractor() *ImageExtractor {
	return &ImageExtractor{}
}

// FromPodSpec extracts all container images from a Pod spec.
func (e *ImageExtractor) FromPodSpec(spec *corev1.PodSpec) []ExtractedImage {
	var images []ExtractedImage

	// Extract from containers
	for i := range spec.Containers {
		container := &spec.Containers[i]
		if container.Image != "" {
			images = append(images, ExtractedImage{
				Image:         container.Image,
				ContainerName: container.Name,
			})
		}
	}

	// Extract from init containers
	for i := range spec.InitContainers {
		container := &spec.InitContainers[i]
		if container.Image != "" {
			images = append(images, ExtractedImage{
				Image:         container.Image,
				ContainerName: container.Name,
			})
		}
	}

	// Extract from ephemeral containers (if supported)
	for i := range spec.EphemeralContainers {
		container := &spec.EphemeralContainers[i]
		if container.Image != "" {
			images = append(images, ExtractedImage{
				Image:         container.Image,
				ContainerName: container.Name,
			})
		}
	}

	return images
}
