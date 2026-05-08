package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMetricsExtraHandlers(t *testing.T) {
	handlers := metricsExtraHandlers()

	healthz, ok := handlers["/healthz"]
	require.True(t, ok)
	require.NotNil(t, healthz)

	readyz, ok := handlers["/readyz"]
	require.True(t, ok)
	require.NotNil(t, readyz)
}

func TestOKHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	res := httptest.NewRecorder()

	okHandler().ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(t, "ok", res.Body.String())
}
