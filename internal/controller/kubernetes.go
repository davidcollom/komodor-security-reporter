package controller

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// LoadKubernetesConfig loads Kubernetes configuration, trying in-cluster first,
// then falling back to kubeconfig file from environment or default location.
func LoadKubernetesConfig(log logrus.FieldLogger, kubeconfigPath string) (*rest.Config, error) {
	// Try in-cluster config first (production)
	cfg, err := rest.InClusterConfig()
	if err == nil {
		log.Info("using in-cluster Kubernetes configuration")
		return cfg, nil
	}

	// If explicit kubeconfig path provided, use it
	if kubeconfigPath != "" {
		log.WithField("kubeconfig", kubeconfigPath).Info("loading Kubernetes configuration from file")

		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("build config from kubeconfig: %w", err)
		}

		return cfg, nil
	}

	// Fall back to kubeconfig from environment or default location
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}

	log.WithField("kubeconfig", kubeconfig).Info("loading Kubernetes configuration from kubeconfig")

	cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("build config from kubeconfig: %w", err)
	}

	return cfg, nil
}
