package trivyoperator

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type reportResource struct {
	name       string
	gvr        schema.GroupVersionResource
	namespaced bool
}

var supportedResources = map[string]reportResource{
	"vulnerabilityreports": {
		name: "vulnerabilityreports",
		gvr: schema.GroupVersionResource{
			Group:    "aquasecurity.github.io",
			Version:  "v1alpha1",
			Resource: "vulnerabilityreports",
		},
		namespaced: true,
	},
	"clustervulnerabilityreports": {
		name: "clustervulnerabilityreports",
		gvr: schema.GroupVersionResource{
			Group:    "aquasecurity.github.io",
			Version:  "v1alpha1",
			Resource: "clustervulnerabilityreports",
		},
		namespaced: false,
	},
}

var defaultResourceNames = []string{"vulnerabilityreports"}

func init() {
	scanners.RegisterScanner("trivy-operator", newScannerFactory)
}

type reportLister interface {
	List(ctx context.Context, resource reportResource) ([]unstructured.Unstructured, error)
}

type dynamicReportLister struct {
	client dynamic.Interface
}

func (c *dynamicReportLister) List(ctx context.Context, resource reportResource) ([]unstructured.Unstructured, error) {
	var (
		list *unstructured.UnstructuredList
		err  error
	)

	if resource.namespaced {
		list, err = c.client.Resource(resource.gvr).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	} else {
		list, err = c.client.Resource(resource.gvr).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, err
	}

	return list.Items, nil
}

func loadKubernetesConfig() (*rest.Config, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("build config from KUBECONFIG: %w", err)
		}

		return cfg, nil
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config: %w", err)
	}

	return cfg, nil
}

func newScannerFactory(scannerCfg config.ScannerConfig, _ string, log logrus.FieldLogger) (scanners.Scanner, error) {
	cfg, err := loadKubernetesConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubernetes config for trivy-operator scanner: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client for trivy-operator scanner: %w", err)
	}

	return NewScanner(&dynamicReportLister{client: dynClient}, scannerCfg.Resources, log)
}

// Scanner reads vulnerability data from Trivy Operator VulnerabilityReport CRDs.
type Scanner struct {
	reportLister reportLister
	resources    []reportResource
	log          logrus.FieldLogger
}

// NewScanner creates a scanner backed by Trivy Operator reports.
func NewScanner(reportLister reportLister, configuredResources []string, log logrus.FieldLogger) (*Scanner, error) {
	resources, err := resolveResources(configuredResources)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		reportLister: reportLister,
		resources:    resources,
		log:          log,
	}, nil
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "trivy-operator"
}

// Scan looks up matching VulnerabilityReport CRDs and normalises the findings.
func (s *Scanner) Scan(ctx context.Context, image scanners.ImageRef) (*scanners.ScanResult, error) {
	allReports := make([]unstructured.Unstructured, 0)

	for _, resource := range s.resources {
		reports, err := s.reportLister.List(ctx, resource)
		if err != nil {
			return nil, fmt.Errorf("list trivy operator resource %s: %w", resource.name, err)
		}

		allReports = append(allReports, reports...)
	}

	matched := filterReportsForImage(allReports, image)
	findings := findingsFromReports(matched)

	result := &scanners.ScanResult{
		Scanner:   s.Name(),
		Image:     image,
		ScannedAt: time.Now().UTC(),
		Summary:   summaryFromFindings(findings),
		Findings:  findings,
	}

	return result, nil
}

func resolveResources(configured []string) ([]reportResource, error) {
	if len(configured) == 0 {
		configured = defaultResourceNames
	}

	resources := make([]reportResource, 0, len(configured))
	for _, resourceName := range configured {
		key := strings.ToLower(strings.TrimSpace(resourceName))

		resource, ok := supportedResources[key]
		if !ok {
			return nil, fmt.Errorf("unsupported trivy-operator resource %q", resourceName)
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

func filterReportsForImage(reports []unstructured.Unstructured, image scanners.ImageRef) []unstructured.Unstructured {
	filtered := make([]unstructured.Unstructured, 0)

	for i := range reports {
		report := &reports[i]

		if reportMatchesImage(report, image) {
			filtered = append(filtered, *report)
		}
	}

	return filtered
}

func reportMatchesImage(report *unstructured.Unstructured, image scanners.ImageRef) bool {
	repository, _, _ := unstructured.NestedString(report.Object, "report", "artifact", "repository")
	tag, _, _ := unstructured.NestedString(report.Object, "report", "artifact", "tag")
	registry, _, _ := unstructured.NestedString(report.Object, "report", "registry", "server")

	if repository == "" || repository != image.Repository {
		return false
	}

	if image.Tag != "" && tag != "" && tag != image.Tag {
		return false
	}

	if registry != "" && !sameRegistry(registry, image.Registry) {
		return false
	}

	return true
}

func sameRegistry(a, b string) bool {
	normalise := func(value string) string {
		value = strings.ToLower(strings.TrimSpace(value))
		switch value {
		case "docker.io", "index.docker.io", "registry-1.docker.io":
			return "docker.io"
		default:
			return value
		}
	}

	if b == "" {
		return true
	}

	return normalise(a) == normalise(b)
}

func findingsFromReports(reports []unstructured.Unstructured) []scanners.Finding {
	seen := make(map[string]struct{})
	findings := make([]scanners.Finding, 0)

	for i := range reports {
		report := &reports[i]

		vulns, found, _ := unstructured.NestedSlice(report.Object, "report", "vulnerabilities")
		if !found {
			continue
		}

		for _, raw := range vulns {
			vuln, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}

			finding := findingFromVulnerability(vuln)

			fingerprint := findingFingerprint(finding)
			if _, exists := seen[fingerprint]; exists {
				continue
			}

			seen[fingerprint] = struct{}{}

			findings = append(findings, finding)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}

		return findings[i].ID < findings[j].ID
	})

	return findings
}

func findingFromVulnerability(vuln map[string]interface{}) scanners.Finding {
	id, _ := vuln["vulnerabilityID"].(string)
	severityText, _ := vuln["severity"].(string)
	resource, _ := vuln["resource"].(string)
	installedVersion, _ := vuln["installedVersion"].(string)
	fixedVersion, _ := vuln["fixedVersion"].(string)
	title, _ := vuln["title"].(string)
	primaryLink, _ := vuln["primaryLink"].(string)

	severity, err := scanners.ParseSeverity(severityText)
	if err != nil {
		severity = scanners.SeverityUnknown
	}

	finding := scanners.Finding{
		ID:          id,
		CVE:         normaliseCVE(id),
		Package:     resource,
		Installed:   installedVersion,
		Fixed:       fixedVersion,
		Severity:    severity,
		Title:       title,
		URL:         primaryLink,
		Exploitable: false,
	}

	return finding
}

func normaliseCVE(id string) string {
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		return id
	}

	return ""
}

func findingFingerprint(finding scanners.Finding) string {
	return strings.Join([]string{
		finding.ID,
		finding.Package,
		finding.Installed,
		finding.Fixed,
		string(finding.Severity),
	}, "|")
}

func summaryFromFindings(findings []scanners.Finding) scanners.VulnerabilitySummary {
	summary := scanners.VulnerabilitySummary{}

	for i := range findings {
		finding := &findings[i]
		switch finding.Severity {
		case scanners.SeverityCritical:
			summary.Critical++
		case scanners.SeverityHigh:
			summary.High++
		case scanners.SeverityMedium:
			summary.Medium++
		case scanners.SeverityLow:
			summary.Low++
		default:
			summary.Unknown++
		}
	}

	return summary
}
