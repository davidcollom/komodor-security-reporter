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
	require.Equal(t, "CVE-2026-3000", result.Findings[0].CVE)
	require.Equal(t, "openssl", result.Findings[0].Package)
	require.Equal(t, scanners.SeverityHigh, result.Findings[0].Severity)
	require.Equal(t, "2.35-r1", result.Findings[1].Fixed)
	require.Equal(t, scanners.SeverityCritical, result.Findings[1].Severity)
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

func TestScannerName(t *testing.T) {
	s := NewScanner("clairctl", logrus.New())
	require.Equal(t, "clair", s.Name())
}
