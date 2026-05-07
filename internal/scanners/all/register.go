package all

// Side-effect imports register built-in scanner factories through init().
import (
	_ "github.com/davidcollom/komodor-security-reporter/internal/scanners/clair"
	_ "github.com/davidcollom/komodor-security-reporter/internal/scanners/snyk"
	_ "github.com/davidcollom/komodor-security-reporter/internal/scanners/trivy"
	_ "github.com/davidcollom/komodor-security-reporter/internal/scanners/wiz"
)
