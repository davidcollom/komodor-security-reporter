package wiz

import (
	"testing"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestParseResult(t *testing.T) {
	sampleOutput := []byte(`{
	  "scan": {
	    "vulnerabilities": [
	      {
	        "id": "WIZ-1",
	        "severity": "critical",
	        "title": "glibc overflow",
	        "packageName": "glibc",
	        "installedVersion": "2.35-r0",
	        "fixedVersion": "2.35-r1",
	        "identifiers": {
	          "CVE": ["CVE-2026-2000"]
	        },
	        "url": "https://security.example/glibc"
	      },
	      {
	        "id": "WIZ-2",
	        "severity": "medium",
	        "name": "openssl",
	        "version": "1.1.1"
	      }
	    ]
	  }
	}`)

	image := scanners.ImageRef{
		Original: "alpine:3.16",
		Resolved: "docker.io/library/alpine:3.16",
	}

	result, err := parseResult(sampleOutput, image)
	require.NoError(t, err)
	require.Len(t, result.Findings, 2)
	require.Equal(t, 1, result.Summary.Critical)
	require.Equal(t, 1, result.Summary.Medium)
	require.Equal(t, "CVE-2026-2000", result.Findings[0].CVE)
	require.Equal(t, "glibc", result.Findings[0].Package)
	require.Equal(t, "2.35-r1", result.Findings[0].Fixed)
	require.Equal(t, scanners.SeverityCritical, result.Findings[0].Severity)
}

func TestParseResultIgnoresNonVulnerabilityObjects(t *testing.T) {
	sampleOutput := []byte(`{
	  "metadata": {
	    "severity": "high"
	  },
	  "summary": {
	    "total": 10
	  }
	}`)

	result, err := parseResult(sampleOutput, scanners.ImageRef{})
	require.NoError(t, err)
	require.Empty(t, result.Findings)
	require.Equal(t, 0, result.Summary.Total())
}

func TestParseResultInvalidJSON(t *testing.T) {
	_, err := parseResult([]byte("invalid json"), scanners.ImageRef{})
	require.Error(t, err)
}

func TestScannerName(t *testing.T) {
	s := NewScanner("wizcli", logrus.New())
	require.Equal(t, "wiz", s.Name())
}
