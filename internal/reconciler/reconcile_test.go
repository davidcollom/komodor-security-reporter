package reconciler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/komodor"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolveNamespacesReturnsConfiguredIncludeList(t *testing.T) {
	recon := &Reconciler{
		clientset: fake.NewSimpleClientset(),
		cfg: &config.Config{
			Namespaces: config.NamespaceConfig{
				Include: []string{"platform", "production"},
			},
		},
		log: logrus.New(),
	}

	namespaces, err := recon.resolveNamespaces(context.Background())

	require.NoError(t, err)
	require.Equal(t, []string{"platform", "production"}, namespaces)
}

func TestResolveNamespacesListsAllClusterNamespacesWhenIncludeEmpty(t *testing.T) {
	recon := &Reconciler{
		clientset: fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "platform"}},
		),
		cfg: &config.Config{},
		log: logrus.New(),
	}

	namespaces, err := recon.resolveNamespaces(context.Background())

	require.NoError(t, err)
	require.Equal(t, []string{"kube-system", "platform", "production"}, namespaces)
}

func TestPublishKubernetesEventCreatesEvent(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
	)

	recon := &Reconciler{
		clientset: clientset,
		log:       logrus.New(),
	}

	scannedAt := time.Now().UTC().Truncate(time.Second)

	err := recon.publishKubernetesEvent(
		context.Background(),
		&stubScanner{name: "trivy"},
		&scanners.ScanResult{
			Image: scanners.ImageRef{Resolved: "docker.io/library/nginx@sha256:abc"},
			Summary: scanners.VulnerabilitySummary{
				High: 1,
			},
			ScannedAt: scannedAt,
		},
		komodor.WorkloadContext{
			Namespace: "default",
			Kind:      "Deployment",
			Name:      "nginx",
		},
	)
	require.NoError(t, err)

	events, err := clientset.CoreV1().Events("default").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, events.Items, 1)

	ev := events.Items[0]
	require.Equal(t, "VulnerabilityScan", ev.Reason)
	require.Equal(t, corev1.EventTypeWarning, ev.Type)
	require.True(t, strings.Contains(ev.Message, "summary=\"critical=0 high=1 medium=0 low=0 total=1\""))
	require.False(t, ev.FirstTimestamp.IsZero(), "FirstTimestamp must be set")
	require.False(t, ev.LastTimestamp.IsZero(), "LastTimestamp must be set")
	require.Equal(t, scannedAt, ev.FirstTimestamp.UTC())
	require.Equal(t, scannedAt, ev.LastTimestamp.UTC())
}

type stubScanner struct {
	name string
}

func (s *stubScanner) Name() string {
	return s.name
}

func (s *stubScanner) Scan(context.Context, scanners.ImageRef) (*scanners.ScanResult, error) {
	return nil, nil
}
