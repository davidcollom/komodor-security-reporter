package registry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		imageStr string
		wantErr  bool
		wantRef  *ImageRef
	}{
		{
			name:     "simple name with default tag",
			imageStr: "ubuntu",
			wantRef: &ImageRef{
				Original:   "ubuntu",
				Registry:   "docker.io",
				Repository: "library/ubuntu",
				Tag:        "latest",
				Digest:     "",
				Resolved:   "ubuntu:latest",
			},
		},
		{
			name:     "simple name with tag",
			imageStr: "ubuntu:22.04",
			wantRef: &ImageRef{
				Original:   "ubuntu:22.04",
				Registry:   "docker.io",
				Repository: "library/ubuntu",
				Tag:        "22.04",
				Digest:     "",
				Resolved:   "ubuntu:22.04",
			},
		},
		{
			name:     "docker hub user image",
			imageStr: "myuser/myapp:1.0",
			wantRef: &ImageRef{
				Original:   "myuser/myapp:1.0",
				Registry:   "docker.io",
				Repository: "myuser/myapp",
				Tag:        "1.0",
				Digest:     "",
				Resolved:   "myuser/myapp:1.0",
			},
		},
		{
			name:     "ghcr.io image with digest",
			imageStr: "ghcr.io/acme/checkout-api@sha256:abc123def456",
			wantRef: &ImageRef{
				Original:   "ghcr.io/acme/checkout-api@sha256:abc123def456",
				Registry:   "ghcr.io",
				Repository: "acme/checkout-api",
				Tag:        "",
				Digest:     "sha256:abc123def456",
				Resolved:   "ghcr.io/acme/checkout-api@sha256:abc123def456",
			},
		},
		{
			name:     "ghcr.io image with tag",
			imageStr: "ghcr.io/acme/checkout-api:1.4.2",
			wantRef: &ImageRef{
				Original:   "ghcr.io/acme/checkout-api:1.4.2",
				Registry:   "ghcr.io",
				Repository: "acme/checkout-api",
				Tag:        "1.4.2",
				Digest:     "",
				Resolved:   "ghcr.io/acme/checkout-api:1.4.2",
			},
		},
		{
			name:     "registry with port and tag",
			imageStr: "registry.example.com:5000/myapp:v1.0",
			wantRef: &ImageRef{
				Original:   "registry.example.com:5000/myapp:v1.0",
				Registry:   "registry.example.com:5000",
				Repository: "myapp",
				Tag:        "v1.0",
				Digest:     "",
				Resolved:   "registry.example.com:5000/myapp:v1.0",
			},
		},
		{
			name:     "empty image",
			imageStr: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := Parse(tt.imageStr)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantRef, ref)
		})
	}
}
