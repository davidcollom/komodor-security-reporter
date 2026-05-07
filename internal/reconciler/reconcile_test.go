package reconciler

import (
	"context"
	"testing"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
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
