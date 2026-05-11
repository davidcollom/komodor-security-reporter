package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Metrics holds all Prometheus metrics for the watcher.
type Metrics struct {
	ImagesObservedTotal        prometheus.Counter
	ImagesResolvedTotal        prometheus.Counter
	ImageResolutionErrorsTotal prometheus.Counter
	ScansTotal                 prometheus.Counter
	ScanErrorsTotal            prometheus.Counter
	ScanDurationSeconds        prometheus.Histogram
	EventsPublishedTotal       prometheus.Counter
	EventPublishErrorsTotal    prometheus.Counter
	DedupeHitsTotal            prometheus.Counter
	ReconcileRunsTotal         *prometheus.CounterVec
	WorkloadsReconciledTotal   *prometheus.CounterVec
	StateLookupsTotal          *prometheus.CounterVec
	StateUpdatesTotal          *prometheus.CounterVec
	EventSkipsTotal            *prometheus.CounterVec
	CacheHitsTotal             *prometheus.CounterVec
	CacheMissesTotal           *prometheus.CounterVec
	CacheEvictionsTotal        *prometheus.CounterVec
}

// NewMetrics creates and registers all metrics.
func NewMetrics() *Metrics {
	registry := promauto.With(ctrlmetrics.Registry)

	return &Metrics{
		ImagesObservedTotal: registry.NewCounter(prometheus.CounterOpts{
			Name: "image_vuln_watcher_images_observed_total",
			Help: "Total number of container images observed",
		}),
		ImagesResolvedTotal: registry.NewCounter(prometheus.CounterOpts{
			Name: "image_vuln_watcher_images_resolved_total",
			Help: "Total number of container images successfully resolved to digest",
		}),
		ImageResolutionErrorsTotal: registry.NewCounter(prometheus.CounterOpts{
			Name: "image_vuln_watcher_image_resolution_errors_total",
			Help: "Total number of image resolution errors",
		}),
		ScansTotal: registry.NewCounter(prometheus.CounterOpts{
			Name: "image_vuln_watcher_scans_total",
			Help: "Total number of vulnerability scans performed",
		}),
		ScanErrorsTotal: registry.NewCounter(prometheus.CounterOpts{
			Name: "image_vuln_watcher_scan_errors_total",
			Help: "Total number of scan errors",
		}),
		ScanDurationSeconds: registry.NewHistogram(prometheus.HistogramOpts{
			Name:    "image_vuln_watcher_scan_duration_seconds",
			Help:    "Scan duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		EventsPublishedTotal: registry.NewCounter(prometheus.CounterOpts{
			Name: "image_vuln_watcher_events_published_total",
			Help: "Total number of events published to Komodor",
		}),
		EventPublishErrorsTotal: registry.NewCounter(prometheus.CounterOpts{
			Name: "image_vuln_watcher_event_publish_errors_total",
			Help: "Total number of event publishing errors",
		}),
		DedupeHitsTotal: registry.NewCounter(prometheus.CounterOpts{
			Name: "image_vuln_watcher_dedupe_hits_total",
			Help: "Total number of events deduplicated",
		}),
		ReconcileRunsTotal: registry.NewCounterVec(prometheus.CounterOpts{
			Name: "image_vuln_watcher_reconcile_runs_total",
			Help: "Total number of reconciliation runs by result",
		}, []string{"result"}),
		WorkloadsReconciledTotal: registry.NewCounterVec(prometheus.CounterOpts{
			Name: "image_vuln_watcher_workloads_reconciled_total",
			Help: "Total number of workload reconciliations by result",
		}, []string{"result"}),
		StateLookupsTotal: registry.NewCounterVec(prometheus.CounterOpts{
			Name: "image_vuln_watcher_state_lookups_total",
			Help: "Total number of state lookups by result",
		}, []string{"result"}),
		StateUpdatesTotal: registry.NewCounterVec(prometheus.CounterOpts{
			Name: "image_vuln_watcher_state_updates_total",
			Help: "Total number of state updates by result",
		}, []string{"result"}),
		EventSkipsTotal: registry.NewCounterVec(prometheus.CounterOpts{
			Name: "image_vuln_watcher_event_skips_total",
			Help: "Total number of event publication skips by reason",
		}, []string{"reason"}),
		CacheHitsTotal: registry.NewCounterVec(prometheus.CounterOpts{
			Name: "image_vuln_watcher_cache_hits_total",
			Help: "Total number of gocache hits by backend type",
		}, []string{"backend"}),
		CacheMissesTotal: registry.NewCounterVec(prometheus.CounterOpts{
			Name: "image_vuln_watcher_cache_misses_total",
			Help: "Total number of gocache misses by backend type",
		}, []string{"backend"}),
		CacheEvictionsTotal: registry.NewCounterVec(prometheus.CounterOpts{
			Name: "image_vuln_watcher_cache_evictions_total",
			Help: "Total number of gocache evictions by backend type",
		}, []string{"backend"}),
	}
}
