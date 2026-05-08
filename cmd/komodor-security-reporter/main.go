package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/bombsimon/logrusr/v3"
	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/controller"
	"github.com/davidcollom/komodor-security-reporter/internal/komodor"
	"github.com/davidcollom/komodor-security-reporter/internal/metrics"
	"github.com/davidcollom/komodor-security-reporter/internal/reconciler"
	"github.com/davidcollom/komodor-security-reporter/internal/registry"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	_ "github.com/davidcollom/komodor-security-reporter/internal/scanners/all"
	"github.com/davidcollom/komodor-security-reporter/internal/state"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	configFile     string
	metricsAddr    string
	logLevel       string
	logFormat      string
	kubeconfig     string
	publishMode    string
	publishModeSet bool
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "komodor-security-reporter",
		Short:         "Watch Kubernetes workloads for image vulnerabilities and publish events to Komodor",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			publishModeSet = cmd.Flags().Changed("publish-mode")
			return run()
		},
	}

	cmd.Flags().StringVar(&configFile, "config", "/etc/komodor-security-reporter/config.yaml", "Path to configuration file")
	cmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8081", "The address the metric endpoint binds to")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	cmd.Flags().StringVar(&logFormat, "log-format", "json", "Log format: json or text")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (for local development; uses in-cluster config in production)")
	cmd.Flags().StringVar(&publishMode, "publish-mode", "komodor", "Publishing mode: komodor, events, or both")

	return cmd
}

func run() error {
	// Setup logging (logrus for application, wrapped for controller-runtime)
	log, err := setupLogging(logLevel, logFormat)
	if err != nil {
		return err
	}

	ctrl.SetLogger(logrusr.New(log))

	log.Info("Starting Komodor Image Vulnerability Watcher")

	cfg, err := loadAndValidateConfig()
	if err != nil {
		return err
	}

	log.WithField("cluster", cfg.ClusterName).Info("loaded configuration")

	k8sConfig, err := controller.LoadKubernetesConfig(log, kubeconfig)
	if err != nil {
		return fmt.Errorf("load Kubernetes config: %w", err)
	}

	mgr, err := createManager(k8sConfig)
	if err != nil {
		return err
	}

	log.WithField("address", metricsAddr).Info("metrics server configured")

	m := metrics.NewMetrics()

	components, err := setupRuntimeComponents(cfg, k8sConfig, log)
	if err != nil {
		return err
	}

	recon := reconciler.NewReconciler(
		components.clientset,
		cfg,
		components.imageExtractor,
		components.resolver,
		components.scannerRegistry,
		components.publisher,
		components.stateStore,
		log,
		m,
	)
	if err := mgr.Add(&initialReconcileRunnable{
		reconciler: recon,
		log:        log,
		timeout:    5 * time.Minute,
	}); err != nil {
		return fmt.Errorf("register initial reconcile runnable: %w", err)
	}

	for _, kind := range cfg.Workloads.Kinds {
		if err := setupReconciler(
			mgr,
			kind,
			cfg,
			components.imageExtractor,
			components.resolver,
			components.scannerRegistry,
			components.publisher,
			log,
			m,
		); err != nil {
			return fmt.Errorf("setup reconciler for %s: %w", kind, err)
		}
	}

	// Start manager (includes metrics server)
	log.Info("Starting controller manager")

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited with error: %w", err)
	}

	return nil
}

func loadAndValidateConfig() (*config.Config, error) {
	cfg, err := config.LoadFromFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("load configuration: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}

	if publishModeSet {
		cfg.Publishing.Mode = publishMode

		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("validate configuration with publish mode override: %w", err)
		}
	}

	return cfg, nil
}

func createManager(k8sConfig *rest.Config) (manager.Manager, error) {
	mgr, err := ctrl.NewManager(k8sConfig, ctrl.Options{
		Scheme:  nil,
		Metrics: server.Options{BindAddress: metricsAddr},
	})
	if err != nil {
		return nil, fmt.Errorf("create manager: %w", err)
	}

	return mgr, nil
}

type runtimeComponents struct {
	imageExtractor  *controller.ImageExtractor
	resolver        *registry.Resolver
	scannerRegistry map[string]scanners.Scanner
	publisher       *komodor.Publisher
	clientset       kubernetes.Interface
	stateStore      *state.Store
}

func setupRuntimeComponents(cfg *config.Config, k8sConfig *rest.Config, log logrus.FieldLogger) (*runtimeComponents, error) {
	scannerRegistry, err := scanners.CreateScannerRegistry(cfg.Scanners.Scanners, log)
	if err != nil {
		return nil, fmt.Errorf("create scanner registry: %w", err)
	}

	var publisher *komodor.Publisher

	if config.PublishToKomodor(cfg.Publishing.Mode) {
		apiKey, err := loadKomodorAPIKey()
		if err != nil {
			return nil, err
		}

		komodorClient := komodor.NewClient(cfg.Komodor.BaseURL, apiKey, log)

		validationCtx, cancelValidation := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelValidation()

		if err := komodorClient.ValidateAPIKey(validationCtx); err != nil {
			return nil, fmt.Errorf("validate Komodor API key: %w", err)
		}

		log.Info("validated Komodor API key")

		publisher = komodor.NewPublisher(komodorClient)
	} else {
		log.WithField("mode", cfg.Publishing.Mode).Info("Komodor API publishing disabled by mode")
	}

	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes clientset: %w", err)
	}

	return &runtimeComponents{
		imageExtractor:  controller.NewImageExtractor(),
		resolver:        registry.NewResolver(log),
		scannerRegistry: scannerRegistry,
		publisher:       publisher,
		clientset:       clientset,
		stateStore:      state.NewStore(clientset, "default", "komodor-security-reporter-state", cfg.State.TTL),
	}, nil
}

func setupLogging(level, format string) (logrus.FieldLogger, error) {
	l := logrus.New()
	l.SetOutput(os.Stdout)

	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		lvl = logrus.InfoLevel
	}

	l.SetLevel(lvl)

	switch format {
	case "", "json":
		l.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339})
	case "text":
		l.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	default:
		return nil, fmt.Errorf("invalid log format %q: supported values are json and text", format)
	}

	return l, nil
}

func loadKomodorAPIKey() (string, error) {
	apiKey := os.Getenv("KOMODOR_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("KOMODOR_API_KEY environment variable is required")
	}

	return apiKey, nil
}

type initialReconcileRunnable struct {
	reconciler *reconciler.Reconciler
	log        logrus.FieldLogger
	timeout    time.Duration
}

func (r *initialReconcileRunnable) Start(ctx context.Context) error {
	reconcileCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	r.log.WithField("timeout", r.timeout.String()).Info("Starting initial reconciliation")

	if err := r.reconciler.ReconcileAll(reconcileCtx); err != nil {
		r.log.WithError(err).Warn("initial reconciliation failed, continuing with watch mode")
		return nil
	}

	r.log.Info("Initial reconciliation completed")

	return nil
}

func setupReconciler(mgr manager.Manager, kind string, cfg *config.Config,
	imageExtractor *controller.ImageExtractor,
	resolver *registry.Resolver,
	scannerRegistry map[string]scanners.Scanner,
	publisher *komodor.Publisher,
	log logrus.FieldLogger,
	m *metrics.Metrics,
) error {
	// This would setup reconcilers for each workload kind
	// For now, return nil as a placeholder
	// Full implementation would be in a separate controller package
	return nil
}
