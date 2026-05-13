package reconciler

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/controller"
	"github.com/davidcollom/komodor-security-reporter/internal/komodor"
	"github.com/davidcollom/komodor-security-reporter/internal/metrics"
	"github.com/davidcollom/komodor-security-reporter/internal/registry"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	stateconfigmap "github.com/davidcollom/komodor-security-reporter/internal/state/backends/configmap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

type benchmarkScannerSpec struct {
	name      string
	failEvery uint64
	severity  scanners.Severity
}

type benchmarkScenario struct {
	name            string
	workloads       int
	scannerMix      []benchmarkScannerSpec
	minimumSeverity string
}

func BenchmarkReconcileAllScenarios(b *testing.B) {
	scenarios := []benchmarkScenario{
		{
			name:      "small-mix-no-failures",
			workloads: 150,
			scannerMix: []benchmarkScannerSpec{
				{name: "trivy", failEvery: 0, severity: scanners.SeverityHigh},
				{name: "clair", failEvery: 0, severity: scanners.SeverityMedium},
			},
			minimumSeverity: "high",
		},
		{
			name:      "large-mix-with-failures",
			workloads: 700,
			scannerMix: []benchmarkScannerSpec{
				{name: "trivy", failEvery: 0, severity: scanners.SeverityHigh},
				{name: "clair", failEvery: 7, severity: scanners.SeverityMedium},
				{name: "snyk", failEvery: 5, severity: scanners.SeverityCritical},
			},
			minimumSeverity: "high",
		},
	}

	if testing.Short() {
		for i := range scenarios {
			scenarios[i].workloads = benchmarkShortWorkloadCount(scenarios[i].workloads)
		}
	}

	for _, scenario := range scenarios {
		scenario := scenario

		b.Run(scenario.name, func(b *testing.B) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
			}))
			defer server.Close()

			ctx := context.Background()

			var reconcileDuration time.Duration

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				b.StopTimer()

				reconciler := buildBenchmarkReconciler(b, scenario, server.URL)

				b.StartTimer()

				start := time.Now()
				err := reconciler.ReconcileAll(ctx)
				reconcileDuration += time.Since(start)

				if err != nil {
					b.Fatalf("reconcile failed: %v", err)
				}
			}

			b.StopTimer()

			totalWorkloads := float64(scenario.workloads * b.N)
			totalScans := totalWorkloads * float64(len(scenario.scannerMix))

			seconds := reconcileDuration.Seconds()

			if seconds > 0 {
				b.ReportMetric(totalWorkloads/seconds, "workloads/s")
				b.ReportMetric(totalScans/seconds, "scans/s")
				b.ReportMetric((seconds*1000)/float64(b.N), "ms/reconcile")
			}
		})
	}
}

func buildBenchmarkReconciler(b *testing.B, scenario benchmarkScenario, komodorURL string) *Reconciler {
	b.Helper()

	namespace := "bench-security"
	clientset := fake.NewSimpleClientset(benchmarkWorkloadObjects(namespace, scenario.workloads)...)

	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)

	registryMap := make(map[string]scanners.Scanner, len(scenario.scannerMix))
	for _, scanner := range scenario.scannerMix {
		registryMap[scanner.name] = &benchmarkScanner{
			name:      scanner.name,
			failEvery: scanner.failEvery,
			severity:  scanner.severity,
		}
	}

	client := komodor.NewClient(komodorURL, "benchmark-api-key", log)

	cfg := &config.Config{
		ClusterName: "benchmark-cluster",
		Namespaces: config.NamespaceConfig{
			Include: []string{namespace},
		},
		Workloads: config.WorkloadsConfig{
			Kinds: []string{"Deployment"},
		},
		Scanners: config.ScannersConfig{
			Concurrency: 12,
		},
		State: config.StateConfig{
			TTL: 24 * time.Hour,
		},
		Publishing: config.PublishingConfig{
			MinimumSeverity:    scenario.minimumSeverity,
			IncludeTopFindings: 5,
			PublishCleanScans:  false,
		},
	}

	return NewReconciler(
		clientset,
		cfg,
		controller.NewImageExtractor(),
		registry.NewResolver(log),
		registryMap,
		map[string]time.Duration{},
		komodor.NewPublisher(client),
		stateconfigmap.NewBackend(clientset, namespace, "benchmark-state", cfg.State.TTL),
		log,
		newUnregisteredBenchmarkMetrics(),
	)
}

func benchmarkShortWorkloadCount(fullCount int) int {
	scaled := fullCount / 10
	if scaled < 30 {
		return 30
	}

	return scaled
}

func benchmarkWorkloadObjects(namespace string, workloads int) []runtime.Object {
	objects := make([]runtime.Object, 0, workloads)

	for i := 0; i < workloads; i++ {
		imageDigest := fmt.Sprintf("sha256:%064x", i+1)
		objects = append(objects, &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      fmt.Sprintf("workload-%04d", i),
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Name:  "app",
							Image: "ghcr.io/example/app@" + imageDigest,
						}},
					},
				},
			},
		})
	}

	return objects
}

type benchmarkScanner struct {
	name      string
	failEvery uint64
	severity  scanners.Severity
}

func (s *benchmarkScanner) Name() string {
	return s.name
}

func (s *benchmarkScanner) Scan(_ context.Context, image scanners.ImageRef) (*scanners.ScanResult, error) {
	if s.failEvery > 0 {
		h := fnv.New64a()

		_, _ = h.Write([]byte(image.Resolved))

		if h.Sum64()%s.failEvery == 0 {
			return nil, fmt.Errorf("simulated scanner failure for %s", image.Resolved)
		}
	}

	result := &scanners.ScanResult{
		Scanner:   s.name,
		Image:     image,
		ScannedAt: time.Now().UTC(),
		Summary:   scanners.VulnerabilitySummary{},
		Findings: []scanners.Finding{
			{
				ID:       "CVE-2026-0001",
				CVE:      "CVE-2026-0001",
				Severity: s.severity,
				Package:  "openssl",
			},
		},
	}

	switch s.severity {
	case scanners.SeverityCritical:
		result.Summary.Critical = 1
	case scanners.SeverityHigh:
		result.Summary.High = 1
	case scanners.SeverityMedium:
		result.Summary.Medium = 1
	case scanners.SeverityLow:
		result.Summary.Low = 1
	default:
		result.Summary.Unknown = 1
	}

	return result, nil
}

func newUnregisteredBenchmarkMetrics() *metrics.Metrics {
	return &metrics.Metrics{
		ImagesObservedTotal:        prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_images_observed_total", Help: "benchmark"}),
		ImagesResolvedTotal:        prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_images_resolved_total", Help: "benchmark"}),
		ImageResolutionErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_image_resolution_errors_total", Help: "benchmark"}),
		ScansTotal:                 prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_scans_total", Help: "benchmark"}),
		ScanErrorsTotal:            prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_scan_errors_total", Help: "benchmark"}),
		ScanDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "bench_scan_duration_seconds",
			Help:    "benchmark",
			Buckets: prometheus.DefBuckets,
		}),
		EventsPublishedTotal:    prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_events_published_total", Help: "benchmark"}),
		EventPublishErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_event_publish_errors_total", Help: "benchmark"}),
		DedupeHitsTotal:         prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_dedupe_hits_total", Help: "benchmark"}),
		ReconcileRunsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bench_reconcile_runs_total",
			Help: "benchmark",
		}, []string{"result"}),
		WorkloadsReconciledTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bench_workloads_reconciled_total",
			Help: "benchmark",
		}, []string{"result"}),
		StateLookupsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bench_state_lookups_total",
			Help: "benchmark",
		}, []string{"result"}),
		StateUpdatesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bench_state_updates_total",
			Help: "benchmark",
		}, []string{"result"}),
		EventSkipsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bench_event_skips_total",
			Help: "benchmark",
		}, []string{"reason"}),
	}
}
