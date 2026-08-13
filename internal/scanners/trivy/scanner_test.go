package trivy

import (
	"context"
	"testing"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestParseResult(t *testing.T) {
	sampleOutput := []byte(`{
	  "Results": [
	    {
	      "Target": "alpine:3.16",
	      "Type": "os",
	      "Vulnerabilities": [
	        {
	          "VulnerabilityID": "CVE-2022-1234",
	          "PkgName": "openssl",
	          "InstalledVersion": "1.1.1",
	          "FixedVersion": "1.1.2",
	          "Severity": "HIGH",
	          "Title": "OpenSSL vulnerability",
	          "Description": "Critical security issue",
	          "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2022-1234"
	        },
	        {
	          "VulnerabilityID": "CVE-2022-5678",
	          "PkgName": "busybox",
	          "InstalledVersion": "1.34.0",
	          "FixedVersion": "1.34.1",
	          "Severity": "CRITICAL",
	          "Title": "Busybox critical issue",
	          "Description": "Critical vulnerability",
	          "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2022-5678"
	        }
	      ]
	    }
	  ]
	}`)

	image := scanners.ImageRef{
		Original:   "alpine:3.16",
		Registry:   "docker.io",
		Repository: "library/alpine",
		Tag:        "3.16",
		Resolved:   "docker.io/library/alpine:3.16",
	}

	result, err := parseResult(sampleOutput, image)

	require.NoError(t, err)
	require.Equal(t, 2, len(result.Findings))
	require.Equal(t, 1, result.Summary.Critical)
	require.Equal(t, 1, result.Summary.High)
	require.Equal(t, 0, result.Summary.Medium)

	// Check first finding
	require.Equal(t, "CVE-2022-1234", result.Findings[0].CVE)
	require.Equal(t, "openssl", result.Findings[0].Package)
	require.Equal(t, scanners.SeverityHigh, result.Findings[0].Severity)
	// Enrichment fields
	require.True(t, result.Findings[0].FixAvailable)
	require.Equal(t, "trivy", result.Findings[0].ScannerAttribution)
}

func TestParseResultEmpty(t *testing.T) {
	sampleOutput := []byte(`{
	  "Results": []
	}`)

	image := scanners.ImageRef{
		Original:   "alpine:3.16",
		Registry:   "docker.io",
		Repository: "library/alpine",
		Tag:        "3.16",
		Resolved:   "docker.io/library/alpine:3.16",
	}

	result, err := parseResult(sampleOutput, image)

	require.NoError(t, err)
	require.Equal(t, 0, len(result.Findings))
	require.Equal(t, 0, result.Summary.Total())
}

func TestParseResultInvalidJSON(t *testing.T) {
	image := scanners.ImageRef{}
	_, err := parseResult([]byte("invalid json"), image)

	require.Error(t, err)
}

func TestScannerName(t *testing.T) {
	s := NewScanner("trivy", logrus.New())
	require.Equal(t, "trivy", s.Name())
}

func TestScannerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	s := NewScanner("trivy", logrus.New())
	ctx := context.Background()

	image := scanners.ImageRef{
		Original:   "alpine:3.16",
		Registry:   "docker.io",
		Repository: "library/alpine",
		Tag:        "3.16",
		Resolved:   "docker.io/library/alpine:3.16",
	}

	// This requires trivy to be installed
	result, err := s.Scan(ctx, image)
	// Don't fail if trivy is not installed (local dev environment)
	if err != nil {
		t.Logf("skipping integration test: %v", err)
		return
	}

	require.NotNil(t, result)
	require.Equal(t, "trivy", result.Scanner)
}
