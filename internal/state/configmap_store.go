package state

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Entry represents stored state for a scanned image.
type Entry struct {
	Fingerprint       string
	LastScannedTime   time.Time
	LastPublishedTime time.Time
	Summary           string // Human-readable summary
}

// Store persists scan state using ConfigMap backend.
type Store struct {
	client    kubernetes.Interface
	namespace string
	configMap string
	ttl       time.Duration
}

// NewStore creates a new state store.
func NewStore(client kubernetes.Interface, namespace, configMapName string, ttl time.Duration) *Store {
	return &Store{
		client:    client,
		namespace: namespace,
		configMap: configMapName,
		ttl:       ttl,
	}
}

// GetEntry retrieves stored state for an image.
func (s *Store) GetEntry(ctx context.Context, key string) (*Entry, error) {
	storageKey := configMapDataKey(key)

	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.configMap, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("get configmap: %w", err)
	}

	data, ok := cm.Data[storageKey]
	if !ok {
		return nil, nil
	}

	entry, err := parseStateEntry(data)
	if err != nil {
		return nil, fmt.Errorf("parse state entry for key %s: %w", key, err)
	}

	if s.isExpired(entry, time.Now()) {
		_ = s.DeleteEntry(ctx, key)
		return nil, nil
	}

	return entry, nil
}

// SetEntry stores state for an image.
func (s *Store) SetEntry(ctx context.Context, key string, entry *Entry) error {
	storageKey := configMapDataKey(key)

	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.configMap, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Create ConfigMap if it doesn't exist
			cm = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      s.configMap,
					Namespace: s.namespace,
				},
				Data: make(map[string]string),
			}

			_, err := s.client.CoreV1().ConfigMaps(s.namespace).Create(ctx, cm, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("create configmap: %w", err)
			}
		} else {
			return fmt.Errorf("get configmap: %w", err)
		}
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}

	cm.Data[storageKey] = formatStateEntry(entry)

	_, err = s.client.CoreV1().ConfigMaps(s.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update configmap: %w", err)
	}

	return nil
}

// DeleteEntry removes state for an image key if it exists.
func (s *Store) DeleteEntry(ctx context.Context, key string) error {
	storageKey := configMapDataKey(key)

	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.configMap, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}

		return fmt.Errorf("get configmap: %w", err)
	}

	if cm.Data == nil {
		return nil
	}

	if _, ok := cm.Data[storageKey]; !ok {
		return nil
	}

	delete(cm.Data, storageKey)

	if _, err := s.client.CoreV1().ConfigMaps(s.namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update configmap: %w", err)
	}

	return nil
}

func configMapDataKey(key string) string {
	return "state_" + base64.RawURLEncoding.EncodeToString([]byte(key))
}

type serializedStateEntry struct {
	Fingerprint       string `json:"fingerprint"`
	LastScannedTime   int64  `json:"lastScannedTime"`
	LastPublishedTime int64  `json:"lastPublishedTime"`
	Summary           string `json:"summary"`
}

func parseStateEntry(data string) (*Entry, error) {
	var serialized serializedStateEntry
	if err := json.Unmarshal([]byte(data), &serialized); err == nil {
		entry := &Entry{Fingerprint: serialized.Fingerprint, Summary: serialized.Summary}
		if serialized.LastScannedTime > 0 {
			entry.LastScannedTime = time.Unix(serialized.LastScannedTime, 0).UTC()
		}

		if serialized.LastPublishedTime > 0 {
			entry.LastPublishedTime = time.Unix(serialized.LastPublishedTime, 0).UTC()
		}

		return entry, nil
	}

	parts := strings.SplitN(data, "|", 4)
	if len(parts) == 4 {
		entry := &Entry{Fingerprint: parts[0], Summary: parts[3]}

		scanned, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse scanned unix timestamp: %w", err)
		}

		published, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse published unix timestamp: %w", err)
		}

		if scanned > 0 {
			entry.LastScannedTime = time.Unix(scanned, 0).UTC()
		}

		if published > 0 {
			entry.LastPublishedTime = time.Unix(published, 0).UTC()
		}

		return entry, nil
	}

	// Backward compatibility: legacy fingerprint-only payload.
	return &Entry{Fingerprint: data}, nil
}

func formatStateEntry(entry *Entry) string {
	payload := serializedStateEntry{
		Fingerprint: entry.Fingerprint,
		Summary:     entry.Summary,
	}
	if !entry.LastScannedTime.IsZero() {
		payload.LastScannedTime = entry.LastScannedTime.Unix()
	}

	if !entry.LastPublishedTime.IsZero() {
		payload.LastPublishedTime = entry.LastPublishedTime.Unix()
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf("%s|%d|%d|%s",
			entry.Fingerprint,
			entry.LastScannedTime.Unix(),
			entry.LastPublishedTime.Unix(),
			entry.Summary,
		)
	}

	return string(data)
}

func (s *Store) isExpired(entry *Entry, now time.Time) bool {
	if entry == nil || s.ttl <= 0 || entry.LastScannedTime.IsZero() {
		return false
	}

	return now.Sub(entry.LastScannedTime) > s.ttl
}
