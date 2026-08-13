package reconciler

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/concurrency"
	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/controller"
	"github.com/davidcollom/komodor-security-reporter/internal/komodor"
	"github.com/davidcollom/komodor-security-reporter/internal/metrics"
	"github.com/davidcollom/komodor-security-reporter/internal/policy"
	"github.com/davidcollom/komodor-security-reporter/internal/registry"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/davidcollom/komodor-security-reporter/internal/state"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Reconciler orchestrates vulnerability scanning and event publishing.
type Reconciler struct {
	clientset             kubernetes.Interface
	cfg                   *config.Config
	imageExtractor        *controller.ImageExtractor
	resolver              *registry.Resolver
	scannerRegistry       map[string]scanners.Scanner
	scannerTimeoutsByName map[string]time.Duration
	publisher             *komodor.Publisher
	stateStore            state.Backend
	log                   logrus.FieldLogger
	metrics               *metrics.Metrics
	runtimePolicy         scannerRuntimePolicy
	circuitBreaker        *scannerCircuitBreaker
	sleep                 func(context.Context, time.Duration) error
	backpressure          *concurrency.AdaptiveLimiter
}

// NewReconciler creates a new reconciler instance.
func NewReconciler(
	clientset kubernetes.Interface,
	cfg *config.Config,
	imageExtractor *controller.ImageExtractor,
	resolver *registry.Resolver,
	scannerRegistry map[string]scanners.Scanner,
	scannerTimeoutsByName map[string]time.Duration,
	publisher *komodor.Publisher,
	stateStore state.Backend,
	log logrus.FieldLogger,
	metrics *metrics.Metrics,
) *Reconciler {
	runtimePolicy := newScannerRuntimePolicy(cfg.Scanners.Runtime)
	effective := config.EffectiveScannersConfig(cfg.Scanners)
	bp := effective.Backpressure

	return &Reconciler{
		clientset:             clientset,
		cfg:                   cfg,
		imageExtractor:        imageExtractor,
		resolver:              resolver,
		scannerRegistry:       scannerRegistry,
		scannerTimeoutsByName: scannerTimeoutsByName,
		publisher:             publisher,
		stateStore:            stateStore,
		log:                   log,
		metrics:               metrics,
		runtimePolicy:         runtimePolicy,
		circuitBreaker:        newScannerCircuitBreaker(runtimePolicy, time.Now),
		sleep:                 sleepWithContext,
		backpressure:          concurrency.NewAdaptiveLimiter(bp.MaxRPS, bp.MinRPS, bp.ErrorRateThreshold),
	}
}

// ReconcileAll performs a full reconciliation of all workloads.
func (r *Reconciler) ReconcileAll(ctx context.Context) error {
	r.log.Info("Starting workload reconciliation")

	namespaces, err := r.resolveNamespaces(ctx)
	if err != nil {
		r.metrics.ReconcileRunsTotal.WithLabelValues("error").Inc()
		return fmt.Errorf("resolve namespaces: %w", err)
	}

	effective := config.EffectiveScannersConfig(r.cfg.Scanners)
	nsConcurrency := effective.NamespaceConcurrency

	nsSemaphore := make(chan struct{}, nsConcurrency)

	var (
		totalWorkloadsMu sync.Mutex
		totalWorkloads   int
		nsWg             sync.WaitGroup
	)

	for _, ns := range namespaces {
		if isExcluded(ns, r.cfg.Namespaces.Exclude) {
			r.log.WithField("namespace", ns).Debug("skipping excluded namespace")
			continue
		}

		nsWg.Add(1)

		if r.metrics != nil && r.metrics.NamespaceScanQueueDepth != nil {
			r.metrics.NamespaceScanQueueDepth.Inc()
		}

		select {
		case nsSemaphore <- struct{}{}:
		case <-ctx.Done():
			nsWg.Done()

			if r.metrics != nil && r.metrics.NamespaceScanQueueDepth != nil {
				r.metrics.NamespaceScanQueueDepth.Dec()
			}

			nsWg.Wait()
			r.metrics.ReconcileRunsTotal.WithLabelValues("error").Inc()

			return fmt.Errorf("namespace queue wait: %w", ctx.Err())
		}

		if r.metrics != nil && r.metrics.NamespaceScanQueueDepth != nil {
			r.metrics.NamespaceScanQueueDepth.Dec()
		}

		go func(ns string) {
			defer nsWg.Done()
			defer func() { <-nsSemaphore }()

			nsLog := r.log.WithField("namespace", ns)
			nsWorkloads := 0

			for _, kind := range r.cfg.Workloads.Kinds {
				workloads, err := r.listWorkloads(ctx, ns, kind)
				if err != nil {
					nsLog.WithError(err).Warnf("failed to list %s workloads", kind)
					continue
				}

				nsWorkloads += len(workloads)
				nsLog.WithFields(logrus.Fields{
					"kind":           kind,
					"workload_count": len(workloads),
				}).Debug("discovered workloads for reconciliation")

				for _, wl := range workloads {
					if err := r.reconcileWorkload(ctx, ns, wl); err != nil {
						r.metrics.WorkloadsReconciledTotal.WithLabelValues("error").Inc()
						r.log.WithFields(logrus.Fields{
							"namespace": ns,
							"kind":      wl.Kind,
							"workload":  wl.Name,
						}).WithError(err).Warn("workload reconciliation failed")

						continue
					}

					r.metrics.WorkloadsReconciledTotal.WithLabelValues("success").Inc()
				}
			}

			totalWorkloadsMu.Lock()
			totalWorkloads += nsWorkloads
			totalWorkloadsMu.Unlock()
		}(ns)
	}

	nsWg.Wait()

	r.log.WithFields(logrus.Fields{
		"namespace_count": len(namespaces),
		"workload_count":  totalWorkloads,
	}).Info("Workload reconciliation completed")
	r.metrics.ReconcileRunsTotal.WithLabelValues("success").Inc()

	return nil
}

func (r *Reconciler) resolveNamespaces(ctx context.Context) ([]string, error) {
	if len(r.cfg.Namespaces.Include) > 0 {
		namespaces := append([]string(nil), r.cfg.Namespaces.Include...)
		sort.Strings(namespaces)

		return namespaces, nil
	}

	namespaceList, err := r.clientset.CoreV1().Namespaces().List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	namespaces := make([]string, 0, len(namespaceList.Items))
	for i := range namespaceList.Items {
		namespace := &namespaceList.Items[i]
		namespaces = append(namespaces, namespace.Name)
	}

	sort.Strings(namespaces)

	r.log.WithField("namespace_count", len(namespaces)).Debug("resolved namespaces from cluster")

	return namespaces, nil
}

// workloadInfo represents a discovered workload.
type workloadInfo struct {
	Kind       string
	Name       string
	UID        string
	APIVersion string
	PodSpec    *corev1.PodSpec
}

type workloadExecutionState struct {
	stateMu sync.Mutex
	errMu   sync.Mutex
	err     error
}

func (s *workloadExecutionState) setError(err error) {
	if err == nil {
		return
	}

	s.errMu.Lock()
	defer s.errMu.Unlock()

	if s.err == nil {
		s.err = err
	}
}

func (s *workloadExecutionState) getError() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()

	return s.err
}

// listWorkloads lists workloads of a given kind in a namespace.
func (r *Reconciler) listWorkloads(ctx context.Context, namespace, kind string) ([]workloadInfo, error) {
	var workloads []workloadInfo

	switch kind {
	case "Deployment":
		deployments, err := r.clientset.AppsV1().Deployments(namespace).List(ctx, v1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list deployments: %w", err)
		}

		for i := range deployments.Items {
			dep := &deployments.Items[i]
			workloads = append(workloads, workloadInfo{
				Kind:       "Deployment",
				Name:       dep.Name,
				UID:        string(dep.UID),
				APIVersion: "apps/v1",
				PodSpec:    &dep.Spec.Template.Spec,
			})
		}

	case "StatefulSet":
		statefulsets, err := r.clientset.AppsV1().StatefulSets(namespace).List(ctx, v1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list statefulsets: %w", err)
		}

		for i := range statefulsets.Items {
			ss := &statefulsets.Items[i]
			workloads = append(workloads, workloadInfo{
				Kind:       "StatefulSet",
				Name:       ss.Name,
				UID:        string(ss.UID),
				APIVersion: "apps/v1",
				PodSpec:    &ss.Spec.Template.Spec,
			})
		}

	case "DaemonSet":
		daemonsets, err := r.clientset.AppsV1().DaemonSets(namespace).List(ctx, v1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list daemonsets: %w", err)
		}

		for i := range daemonsets.Items {
			ds := &daemonsets.Items[i]
			workloads = append(workloads, workloadInfo{
				Kind:       "DaemonSet",
				Name:       ds.Name,
				UID:        string(ds.UID),
				APIVersion: "apps/v1",
				PodSpec:    &ds.Spec.Template.Spec,
			})
		}
	}

	return workloads, nil
}

// reconcileWorkload reconciles a single workload.
func (r *Reconciler) reconcileWorkload(ctx context.Context, namespace string, wl workloadInfo) error {
	wlLog := r.log.WithFields(logrus.Fields{
		"namespace": namespace,
		"kind":      wl.Kind,
		"workload":  wl.Name,
	})
	wlLog.Debug("reconciling workload")

	// Extract images from pod spec
	extractedImages := r.imageExtractor.FromPodSpec(wl.PodSpec)
	r.metrics.ImagesObservedTotal.Add(float64(len(extractedImages)))
	wlLog.WithField("image_count", len(extractedImages)).Debug("extracted images from workload")

	if len(extractedImages) == 0 {
		wlLog.Debug("no images found in workload pod spec")
	}

	semaphore := make(chan struct{}, r.cfg.Scanners.Concurrency)

	var scanWaitGroup sync.WaitGroup

	execState := &workloadExecutionState{}

	for _, extractedImg := range extractedImages {
		resolved, scanImageRef, imgLog, ok := r.prepareScanImage(ctx, extractedImg, wlLog)
		if !ok {
			continue
		}

		for _, scanner := range r.scannerRegistry {
			scanWaitGroup.Add(1)

			if r.metrics != nil && r.metrics.ScanQueueDepth != nil {
				r.metrics.ScanQueueDepth.Inc()
			}

			waitStart := time.Now()

			semaphore <- struct{}{}

			waitDuration := time.Since(waitStart)

			if r.metrics != nil && r.metrics.ScanQueueDepth != nil {
				r.metrics.ScanQueueDepth.Dec()
			}

			if r.metrics != nil && r.metrics.ScanQueueWaitSeconds != nil {
				r.metrics.ScanQueueWaitSeconds.Observe(waitDuration.Seconds())
			}

			// Apply adaptive backpressure before dispatching the scan goroutine.
			// A cancelled context causes Wait to return immediately with an error,
			// so we treat that as a signal to stop dispatching.
			if err := r.backpressure.Wait(ctx); err != nil {
				scanWaitGroup.Done()
				<-semaphore

				return fmt.Errorf("backpressure wait: %w", err)
			}

			if r.metrics != nil && r.metrics.ScansInFlight != nil {
				r.metrics.ScansInFlight.Inc()
			}

			go r.runScannerForImage(
				ctx,
				namespace,
				wl,
				extractedImg,
				resolved,
				scanImageRef,
				scanner,
				imgLog,
				semaphore,
				&scanWaitGroup,
				execState,
			)
		}
	}

	scanWaitGroup.Wait()

	return execState.getError()
}

func (r *Reconciler) prepareScanImage(ctx context.Context, extractedImg controller.ExtractedImage, wlLog *logrus.Entry) (*registry.ImageRef, scanners.ImageRef, *logrus.Entry, bool) {
	imgLog := wlLog.WithFields(logrus.Fields{
		"image":     extractedImg.Image,
		"container": extractedImg.ContainerName,
	})
	imgLog.Debug("processing extracted image")

	imageRef, err := registry.Parse(extractedImg.Image)
	if err != nil {
		imgLog.WithError(err).Warn("failed to parse image reference")
		return nil, scanners.ImageRef{}, imgLog, false
	}

	resolved, err := r.resolver.Resolve(ctx, imageRef)
	if err != nil {
		imgLog.WithError(err).Warn("failed to resolve image digest")
		r.metrics.ImageResolutionErrorsTotal.Inc()

		return nil, scanners.ImageRef{}, imgLog, false
	}

	r.metrics.ImagesResolvedTotal.Inc()

	imgLog = imgLog.WithField("digest", resolved.Digest)
	imgLog.Debug("resolved image digest")

	scanImageRef := scanners.ImageRef{
		Original:   resolved.Original,
		Registry:   resolved.Registry,
		Repository: resolved.Repository,
		Tag:        resolved.Tag,
		Digest:     resolved.Digest,
		Resolved:   resolved.Resolved,
	}

	return resolved, scanImageRef, imgLog, true
}

func (r *Reconciler) runScannerForImage(
	ctx context.Context,
	namespace string,
	wl workloadInfo,
	extractedImg controller.ExtractedImage,
	resolved *registry.ImageRef,
	scanImageRef scanners.ImageRef,
	scanner scanners.Scanner,
	imgLog *logrus.Entry,
	semaphore chan struct{},
	scanWaitGroup *sync.WaitGroup,
	execState *workloadExecutionState,
) {
	defer scanWaitGroup.Done()
	defer func() { <-semaphore }()
	defer func() {
		if r.metrics != nil && r.metrics.ScansInFlight != nil {
			r.metrics.ScansInFlight.Dec()
		}
	}()

	scannerLog := imgLog.WithField("scanner", scanner.Name())
	scannerLog.Debug("starting vulnerability scan")

	scanResult, scanDuration, errClass, err := r.executeScannerWithResilience(ctx, scanner, scanImageRef)
	if err != nil {
		r.backpressure.RecordResult(true)
		scannerLog.WithFields(logrus.Fields{
			"error_class": errClass,
		}).WithError(err).Warn("scan failed")
		r.metrics.ScanErrorsTotal.Inc()

		if r.metrics.ScannerErrorClassTotal != nil {
			r.metrics.ScannerErrorClassTotal.WithLabelValues(scanner.Name(), string(errClass)).Inc()
		}

		if errClass == scannerErrorClassCircuitOpen && r.metrics.ScannerSkippedTotal != nil {
			r.metrics.ScannerSkippedTotal.WithLabelValues(scanner.Name(), "circuit_open").Inc()
		}

		execState.setError(err)

		return
	}

	r.metrics.ScansTotal.Inc()
	r.metrics.ScanDurationSeconds.Observe(scanDuration)
	r.backpressure.RecordResult(false)
	scannerLog.WithFields(logrus.Fields{
		"duration_seconds": scanDuration,
		"finding_count":    scanResult.Summary.Total(),
	}).Debug("scan completed")

	workloadCtx := komodor.WorkloadContext{
		ClusterName: r.cfg.ClusterName,
		Namespace:   namespace,
		Kind:        wl.Kind,
		Name:        wl.Name,
		UID:         wl.UID,
		APIVersion:  wl.APIVersion,
		Container:   extractedImg.ContainerName,
	}

	eventOpts := komodor.EventOptions{
		MinimumSeverity:    r.cfg.Publishing.MinimumSeverity,
		IncludeTopFindings: r.cfg.Publishing.IncludeTopFindings,
		PublishCleanScans:  r.cfg.Publishing.PublishCleanScans,
	}

	r.handleScanResultStateAndPublish(ctx, scannerLog, scanner, resolved, scanResult, workloadCtx, eventOpts, &execState.stateMu)
}

func (r *Reconciler) handleScanResultStateAndPublish(
	ctx context.Context,
	scannerLog *logrus.Entry,
	scanner scanners.Scanner,
	resolved *registry.ImageRef,
	scanResult *scanners.ScanResult,
	workloadCtx komodor.WorkloadContext,
	eventOpts komodor.EventOptions,
	stateMu *sync.Mutex,
) {
	stateMu.Lock()
	defer stateMu.Unlock()

	stateKey := fmt.Sprintf("%s/%s", resolved.Digest, scanner.Name())
	latestDigestKey := fmt.Sprintf("latest/%s/%s:%s/%s", resolved.Registry, resolved.Repository, resolved.Tag, scanner.Name())

	r.cleanupPreviousDigestState(ctx, scannerLog, latestDigestKey, stateKey)

	now := time.Now().UTC()
	if err := r.stateStore.SetEntry(ctx, latestDigestKey, &state.Entry{
		Fingerprint:       stateKey,
		LastScannedTime:   now,
		LastPublishedTime: now,
		Summary:           resolved.Digest,
	}); err != nil {
		scannerLog.WithError(err).Warn("failed to update latest digest state")
	}

	lastFingerprint := r.loadLastFingerprint(ctx, scannerLog, stateKey)
	if !policy.EvaluatePublish(scanResult, lastFingerprint, false) {
		r.metrics.DedupeHitsTotal.Inc()
		r.metrics.EventSkipsTotal.WithLabelValues("deduplicated").Inc()
		scannerLog.Debug("skipping event publication (deduplicated)")

		return
	}

	if !komodor.ShouldPublish(scanResult, eventOpts) {
		r.metrics.EventSkipsTotal.WithLabelValues("severity_threshold").Inc()
		scannerLog.Debug("skipping event publication (severity threshold not met)")

		return
	}

	publishedCount := 0
	mode := r.cfg.Publishing.Mode

	if config.PublishToKomodor(mode) {
		if r.publisher == nil {
			scannerLog.Warn("Komodor publisher is not configured")
			r.metrics.EventPublishErrorsTotal.Inc()
		} else {
			event := komodor.EventFromScanResult(scanResult, workloadCtx, eventOpts)
			if err := r.publisher.Publish(ctx, event); err != nil {
				scannerLog.WithError(err).Warn("failed to publish Komodor event")
				r.metrics.EventPublishErrorsTotal.Inc()
			} else {
				publishedCount++
			}
		}
	}

	if config.PublishToEvents(mode) {
		if err := r.publishKubernetesEvent(ctx, scanner, scanResult, workloadCtx); err != nil {
			scannerLog.WithError(err).Warn("failed to publish Kubernetes event")
			r.metrics.EventPublishErrorsTotal.Inc()
		} else {
			publishedCount++
		}
	}

	if publishedCount == 0 {
		return
	}

	r.metrics.EventsPublishedTotal.Inc()
	scannerLog.WithFields(logrus.Fields{
		"mode":          mode,
		"publish_count": publishedCount,
	}).Info("event published")

	stateEntry := &state.Entry{
		Fingerprint:       policy.Fingerprint(scanResult),
		LastScannedTime:   now,
		LastPublishedTime: now,
		Summary:           fmt.Sprintf("%d findings", scanResult.Summary.Total()),
	}
	if err := r.stateStore.SetEntry(ctx, stateKey, stateEntry); err != nil {
		r.metrics.StateUpdatesTotal.WithLabelValues("error").Inc()
		scannerLog.WithError(err).Warn("failed to update state")

		return
	}

	r.metrics.StateUpdatesTotal.WithLabelValues("success").Inc()
	scannerLog.WithFields(logrus.Fields{"state_key": stateKey, "summary": stateEntry.Summary}).Debug("updated state entry")
}

func (r *Reconciler) publishKubernetesEvent(
	ctx context.Context,
	scanner scanners.Scanner,
	scanResult *scanners.ScanResult,
	workloadCtx komodor.WorkloadContext,
) error {
	if r.clientset == nil {
		return fmt.Errorf("kubernetes clientset is not configured")
	}

	eventType := corev1.EventTypeNormal
	if scanResult.Summary.Total() > 0 {
		eventType = corev1.EventTypeWarning
	}

	summary := fmt.Sprintf(
		"critical=%d high=%d medium=%d low=%d total=%d",
		scanResult.Summary.Critical,
		scanResult.Summary.High,
		scanResult.Summary.Medium,
		scanResult.Summary.Low,
		scanResult.Summary.Total(),
	)

	message := fmt.Sprintf(
		"summary=%q scanner=%s image=%s findings=%d (critical=%d high=%d medium=%d low=%d)",
		summary,
		scanner.Name(),
		scanResult.Image.Resolved,
		scanResult.Summary.Total(),
		scanResult.Summary.Critical,
		scanResult.Summary.High,
		scanResult.Summary.Medium,
		scanResult.Summary.Low,
	)

	now := v1.NewTime(scanResult.ScannedAt.UTC())

	_, err := r.clientset.CoreV1().Events(workloadCtx.Namespace).Create(ctx, &corev1.Event{
		ObjectMeta: v1.ObjectMeta{
			Namespace:    workloadCtx.Namespace,
			GenerateName: "komodor-security-report-",
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       workloadCtx.Kind,
			Namespace:  workloadCtx.Namespace,
			Name:       workloadCtx.Name,
			UID:        types.UID(workloadCtx.UID),
			APIVersion: workloadCtx.APIVersion,
		},
		Reason:              "VulnerabilityScan",
		Action:              "Scan",
		Message:             message,
		Type:                eventType,
		FirstTimestamp:      now,
		LastTimestamp:       now,
		EventTime:           v1.NewMicroTime(scanResult.ScannedAt.UTC()),
		ReportingController: "komodor-security-reporter",
		ReportingInstance:   workloadCtx.Name,
		Source: corev1.EventSource{
			Component: "komodor-security-reporter",
		},
	}, v1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create kubernetes event: %w", err)
	}

	return nil
}

func (r *Reconciler) cleanupPreviousDigestState(ctx context.Context, scannerLog *logrus.Entry, latestDigestKey, stateKey string) {
	latestDigestEntry, err := r.stateStore.GetEntry(ctx, latestDigestKey)
	if err != nil {
		scannerLog.WithError(err).Warn("failed to load latest digest state")
		return
	}

	if latestDigestEntry == nil || latestDigestEntry.Fingerprint == "" || latestDigestEntry.Fingerprint == stateKey {
		return
	}

	if err := r.stateStore.DeleteEntry(ctx, latestDigestEntry.Fingerprint); err != nil {
		scannerLog.WithFields(logrus.Fields{
			"previous_state_key": latestDigestEntry.Fingerprint,
			"current_state_key":  stateKey,
		}).WithError(err).Warn("failed to delete previous digest state")

		return
	}

	scannerLog.WithFields(logrus.Fields{
		"previous_state_key": latestDigestEntry.Fingerprint,
		"current_state_key":  stateKey,
	}).Debug("deleted previous digest state after digest change")
}

func (r *Reconciler) loadLastFingerprint(ctx context.Context, scannerLog *logrus.Entry, stateKey string) string {
	lastEntry, err := r.stateStore.GetEntry(ctx, stateKey)
	if err != nil {
		r.metrics.StateLookupsTotal.WithLabelValues("error").Inc()
		scannerLog.WithError(err).Warn("failed to get state entry")

		return ""
	}

	if lastEntry == nil {
		r.metrics.StateLookupsTotal.WithLabelValues("miss").Inc()
		scannerLog.WithField("state_key", stateKey).Debug("no existing state entry found")

		return ""
	}

	r.metrics.StateLookupsTotal.WithLabelValues("hit").Inc()
	scannerLog.WithFields(logrus.Fields{
		"state_key":         stateKey,
		"last_scanned_at":   lastEntry.LastScannedTime,
		"last_published_at": lastEntry.LastPublishedTime,
		"summary":           lastEntry.Summary,
	}).Debug("loaded existing state entry")

	return lastEntry.Fingerprint
}

// isExcluded checks if a namespace is in the exclusion list.
func isExcluded(ns string, exclusions []string) bool {
	for _, excl := range exclusions {
		if ns == excl {
			return true
		}
	}

	return false
}
