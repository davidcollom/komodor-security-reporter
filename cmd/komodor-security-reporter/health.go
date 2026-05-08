package main

import "net/http"

func metricsExtraHandlers() map[string]http.Handler {
	ok := okHandler()

	return map[string]http.Handler{
		"/healthz": ok,
		"/readyz":  ok,
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}
