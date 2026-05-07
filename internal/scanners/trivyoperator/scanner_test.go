package trivyoperator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type fakeReportLister struct {
	reportsByResource map[string][]unstructured.Unstructured
	errByResource     map[string]error
	listCalls         map[string]int
}

func (f *fakeReportLister) List(_ context.Context, resource reportResource) ([]unstructured.Unstructured, error) {
	if f.listCalls != nil {
		f.listCalls[resource.name]++
	}

	if err, ok := f.errByResource[resource.name]; ok {
		return nil, err
	}

	return f.reportsByResource[resource.name], nil
}

func TestScanReturnsFindingsFromMatchingReports(t *testing.T) {
	scanner, err := NewScanner(&fakeReportLister{reportsByResource: map[string][]unstructured.Unstructured{
		"vulnerabilityreports": {
			buildReport("library/nginx", "1.16", "sha256:abc", "index.docker.io", []map[string]interface{}{
				{
					"vulnerabilityID":  "CVE-2020-27350",
					"severity":         "MEDIUM",
					"resource":         "apt",
					"installedVersion": "1.8.2",
					"fixedVersion":     "1.8.2.2",
					"title":            "apt vulnerability",
					"primaryLink":      "https://avd.aquasec.com/nvd/cve-2020-27350",
				},
				{
					"vulnerabilityID":  "CVE-2019-20367",
					"severity":         "CRITICAL",
					"resource":         "libbsd0",
					"installedVersion": "0.9.1-2",
					"fixedVersion":     "0.9.1-2+deb10u1",
					"title":            "libbsd0 vulnerability",
					"primaryLink":      "https://avd.aquasec.com/nvd/cve-2019-20367",
				},
			}),
		},
	}}, nil, logrus.New())
	require.NoError(t, err)

	result, err := scanner.Scan(context.Background(), scanners.ImageRef{
		Original:   "nginx:1.16",
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "1.16",
		Resolved:   "docker.io/library/nginx@sha256:abc",
	})

	require.NoError(t, err)
	require.Equal(t, "trivy-operator", result.Scanner)
	require.Len(t, result.Findings, 2)
	require.Equal(t, 1, result.Summary.Critical)
	require.Equal(t, 1, result.Summary.Medium)
}

func TestScanIgnoresReportsForOtherImages(t *testing.T) {
	scanner, err := NewScanner(&fakeReportLister{reportsByResource: map[string][]unstructured.Unstructured{
		"vulnerabilityreports": {
			buildReport("library/redis", "7.2", "", "docker.io", []map[string]interface{}{{
				"vulnerabilityID": "CVE-2020-0001",
				"severity":        "HIGH",
				"resource":        "redis",
			}}),
		},
	}}, nil, logrus.New())
	require.NoError(t, err)

	result, err := scanner.Scan(context.Background(), scanners.ImageRef{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "1.16",
	})

	require.NoError(t, err)
	require.Len(t, result.Findings, 0)
	require.Equal(t, 0, result.Summary.Total())
}

func TestScanDeduplicatesFindingsAcrossReports(t *testing.T) {
	vuln := map[string]interface{}{
		"vulnerabilityID":  "CVE-2020-27350",
		"severity":         "MEDIUM",
		"resource":         "apt",
		"installedVersion": "1.8.2",
		"fixedVersion":     "1.8.2.2",
		"title":            "apt vulnerability",
	}

	scanner, err := NewScanner(&fakeReportLister{reportsByResource: map[string][]unstructured.Unstructured{
		"vulnerabilityreports": {
			buildReport("library/nginx", "1.16", "", "docker.io", []map[string]interface{}{vuln}),
			buildReport("library/nginx", "1.16", "", "docker.io", []map[string]interface{}{vuln}),
		},
	}}, nil, logrus.New())
	require.NoError(t, err)

	result, err := scanner.Scan(context.Background(), scanners.ImageRef{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "1.16",
	})

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	require.Equal(t, 1, result.Summary.Medium)
}

func TestScanReturnsClientError(t *testing.T) {
	scanner, err := NewScanner(&fakeReportLister{errByResource: map[string]error{
		"vulnerabilityreports": fmt.Errorf("boom"),
	}}, nil, logrus.New())
	require.NoError(t, err)

	_, err = scanner.Scan(context.Background(), scanners.ImageRef{})

	require.Error(t, err)
	require.Contains(t, err.Error(), "list trivy operator resource")
}

func TestScannerName(t *testing.T) {
	scanner, err := NewScanner(&fakeReportLister{}, nil, logrus.New())
	require.NoError(t, err)

	require.Equal(t, "trivy-operator", scanner.Name())
}

func TestNewScannerReturnsErrorForUnsupportedResource(t *testing.T) {
	_, err := NewScanner(&fakeReportLister{}, []string{"configauditreports"}, logrus.New())

	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported trivy-operator resource")
}

func TestScanIgnoresDigestMismatchesForDigestPinnedImages(t *testing.T) {
	scanner, err := NewScanner(&fakeReportLister{reportsByResource: map[string][]unstructured.Unstructured{
		"vulnerabilityreports": {
			buildReport("library/nginx", "1.16", "sha256:def", "docker.io", []map[string]interface{}{{
				"vulnerabilityID": "CVE-2020-0001",
				"severity":        "HIGH",
				"resource":        "nginx",
			}}),
		},
	}}, nil, logrus.New())
	require.NoError(t, err)

	result, err := scanner.Scan(context.Background(), scanners.ImageRef{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Digest:     "sha256:abc",
	})

	require.NoError(t, err)
	require.Len(t, result.Findings, 0)
}

func TestScanMatchesDigestPinnedImagesByDigest(t *testing.T) {
	scanner, err := NewScanner(&fakeReportLister{reportsByResource: map[string][]unstructured.Unstructured{
		"vulnerabilityreports": {
			buildReport("library/nginx", "1.16", "SHA256:ABC", "docker.io", []map[string]interface{}{{
				"vulnerabilityID": "CVE-2020-0001",
				"severity":        "HIGH",
				"resource":        "nginx",
			}}),
		},
	}}, nil, logrus.New())
	require.NoError(t, err)

	result, err := scanner.Scan(context.Background(), scanners.ImageRef{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Digest:     "sha256:abc",
	})

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
}

func TestScanCanonicalisesLowerCaseCVEIdentifiers(t *testing.T) {
	scanner, err := NewScanner(&fakeReportLister{reportsByResource: map[string][]unstructured.Unstructured{
		"vulnerabilityreports": {
			buildReport("library/nginx", "1.16", "", "docker.io", []map[string]interface{}{{
				"vulnerabilityID": "cve-2020-0001",
				"severity":        "HIGH",
				"resource":        "nginx",
			}}),
		},
	}}, nil, logrus.New())
	require.NoError(t, err)

	result, err := scanner.Scan(context.Background(), scanners.ImageRef{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "1.16",
	})

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "CVE-2020-0001", result.Findings[0].CVE)
}

func TestScanCachesReportListsAcrossCalls(t *testing.T) {
	lister := &fakeReportLister{
		reportsByResource: map[string][]unstructured.Unstructured{
			"vulnerabilityreports": {
				buildReport("library/nginx", "1.16", "", "docker.io", []map[string]interface{}{{
					"vulnerabilityID": "CVE-2020-0001",
					"severity":        "HIGH",
					"resource":        "nginx",
				}}),
			},
		},
		listCalls: map[string]int{},
	}

	scanner, err := NewScanner(lister, nil, logrus.New())
	require.NoError(t, err)

	now := time.Date(2026, time.May, 7, 21, 30, 0, 0, time.UTC)
	scanner.now = func() time.Time { return now }
	scanner.cacheTTL = time.Minute

	_, err = scanner.Scan(context.Background(), scanners.ImageRef{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "1.16",
	})
	require.NoError(t, err)

	now = now.Add(30 * time.Second)
	_, err = scanner.Scan(context.Background(), scanners.ImageRef{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "1.16",
	})
	require.NoError(t, err)

	require.Equal(t, 1, lister.listCalls["vulnerabilityreports"])
}

func buildReport(repository, tag, digest, registry string, vulnerabilities []map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"report": map[string]interface{}{
			"artifact": map[string]interface{}{
				"repository": repository,
				"tag":        tag,
				"digest":     digest,
			},
			"registry": map[string]interface{}{
				"server": registry,
			},
			"vulnerabilities": toInterfaceSlice(vulnerabilities),
		},
	}}
}

func toInterfaceSlice(in []map[string]interface{}) []interface{} {
	out := make([]interface{}, 0, len(in))
	for i := range in {
		out = append(out, in[i])
	}

	return out
}
