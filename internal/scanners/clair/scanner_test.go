package clair

import (
	"testing"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestParseResult(t *testing.T) {
	sampleOutput := []byte(`{
	  "report": {
	    "vulnerabilities": [
	      {
	        "vulnerability": "CVE-2026-3000",
	        "severity": "High",
	        "package": "openssl",
	        "installedVersion": "1.1.1",
	        "fixedVersion": "1.1.2",
	        "links": ["https://security.example/CVE-2026-3000"],
	        "title": "OpenSSL issue"
	      },
	      {
	        "id": "CLAIR-2",
	        "normalizedSeverity": "critical",
	        "featureName": "glibc",
	        "featureVersion": "2.35-r0",
	        "fixedby": "2.35-r1",
	        "name": "glibc overflow",
	        "url": "https://security.example/glibc"
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
	require.Equal(t, 1, result.Summary.High)

	byID := map[string]scanners.Finding{}
	for _, finding := range result.Findings {
		byID[finding.ID] = finding
	}

	first, ok := byID["CVE-2026-3000"]
	require.True(t, ok)
	require.Equal(t, "CVE-2026-3000", first.CVE)
	require.Equal(t, "openssl", first.Package)
	require.Equal(t, scanners.SeverityHigh, first.Severity)

	second, ok := byID["CLAIR-2"]
	require.True(t, ok)
	require.Equal(t, "2.35-r1", second.Fixed)
	require.Equal(t, scanners.SeverityCritical, second.Severity)
}

func TestParseResultDedupe(t *testing.T) {
	sampleOutput := []byte(`{
	  "report": {
	    "vulnerabilities": [
	      {
	        "id": "CVE-2026-3000",
	        "severity": "high",
	        "package": "openssl",
	        "version": "1.1.1"
	      },
	      {
	        "id": "CVE-2026-3000",
	        "severity": "high",
	        "package": "openssl",
	        "version": "1.1.1"
	      }
	    ]
	  }
	}`)

	result, err := parseResult(sampleOutput, scanners.ImageRef{})
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	require.Equal(t, 1, result.Summary.High)
}

func TestParseResultInvalidJSON(t *testing.T) {
	_, err := parseResult([]byte("invalid json"), scanners.ImageRef{})
	require.Error(t, err)
}

func TestParseResultDedupeUsesNameFallbackIdentity(t *testing.T) {
	sampleOutput := []byte(`{
	  "report": {
	    "vulnerabilities": [
	      {
	        "name": "CVE-2026-3000",
	        "severity": "high",
	        "package": "openssl",
	        "version": "1.1.1"
	      },
	      {
	        "name": "CVE-2026-3000",
	        "severity": "high",
	        "package": "openssl",
	        "version": "1.1.1"
	      }
	    ]
	  }
	}`)

	result, err := parseResult(sampleOutput, scanners.ImageRef{})
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	require.Equal(t, 1, result.Summary.High)
}

func TestScannerName(t *testing.T) {
	s := NewScanner("clairctl", logrus.New())
	require.Equal(t, "clair", s.Name())
}

func TestDefaultBinary(t *testing.T) {
	require.Equal(t, "clairctl", defaultBinary(""))
	require.Equal(t, "clairctl", defaultBinary("clair"))
	require.Equal(t, "/usr/local/bin/clairctl", defaultBinary("/usr/local/bin/clairctl"))
}
