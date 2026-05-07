package snyk

import (
	"testing"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestParseResult(t *testing.T) {
	sampleOutput := []byte(`{
	  "ok": false,
	  "vulnerabilities": [
	    {
	      "id": "SNYK-ALPINE-OPENSSL-1",
	      "packageName": "openssl",
	      "version": "1.1.1",
	      "severity": "high",
	      "title": "OpenSSL vulnerability",
	      "fixedIn": ["1.1.2"],
	      "identifiers": {
	        "CVE": ["CVE-2026-1000"]
	      },
	      "references": ["https://security.example/openssl"]
	    }
	  ],
	  "applications": [
	    {
	      "vulnerabilities": [
	        {
	          "id": "SNYK-JS-LODASH-1",
	          "packageName": "lodash",
	          "version": "4.17.20",
	          "severity": "critical",
	          "title": "Prototype Pollution",
	          "fixedIn": ["4.17.21"],
	          "identifiers": {
	            "CVE": ["CVE-2021-23337"]
	          },
	          "url": "https://security.example/lodash"
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
	require.Len(t, result.Findings, 2)
	require.Equal(t, 1, result.Summary.Critical)
	require.Equal(t, 1, result.Summary.High)
	require.Equal(t, "CVE-2026-1000", result.Findings[0].CVE)
	require.Equal(t, "openssl", result.Findings[0].Package)
	require.Equal(t, scanners.SeverityHigh, result.Findings[0].Severity)
	require.Equal(t, "4.17.21", result.Findings[1].Fixed)
}

func TestParseResultSupportsArrayOutput(t *testing.T) {
	sampleOutput := []byte(`[
	  {
	    "vulnerabilities": [
	      {
	        "id": "SNYK-ALPINE-OPENSSL-1",
	        "packageName": "openssl",
	        "version": "1.1.1",
	        "severity": "medium",
	        "title": "OpenSSL vulnerability"
	      }
	    ]
	  }
	]`)

	result, err := parseResult(sampleOutput, scanners.ImageRef{})

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	require.Equal(t, 1, result.Summary.Medium)
}

func TestParseResultInvalidJSON(t *testing.T) {
	_, err := parseResult([]byte("invalid json"), scanners.ImageRef{})
	require.Error(t, err)
}

func TestScannerName(t *testing.T) {
	s := NewScanner("snyk", logrus.New())
	require.Equal(t, "snyk", s.Name())
}
