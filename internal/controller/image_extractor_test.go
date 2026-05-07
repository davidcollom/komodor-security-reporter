package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestImageExtractorFromPodSpec(t *testing.T) {
	extractor := NewImageExtractor()

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:  "main",
				Image: "ghcr.io/acme/app:1.0",
			},
			{
				Name:  "sidecar",
				Image: "ghcr.io/acme/sidecar:latest",
			},
		},
		InitContainers: []corev1.Container{
			{
				Name:  "init",
				Image: "ghcr.io/acme/init:1.0",
			},
		},
	}

	images := extractor.FromPodSpec(spec)

	require.Equal(t, 3, len(images))
	require.Equal(t, "main", images[0].ContainerName)
	require.Equal(t, "ghcr.io/acme/app:1.0", images[0].Image)
	require.Equal(t, "init", images[2].ContainerName)
	require.Equal(t, "ghcr.io/acme/init:1.0", images[2].Image)
}

func TestImageExtractorEmpty(t *testing.T) {
	extractor := NewImageExtractor()

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{},
	}

	images := extractor.FromPodSpec(spec)

	require.Empty(t, images)
}
