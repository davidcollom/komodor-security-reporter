# komodor-security-reporter

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

Kubernetes-native image vulnerability watcher for Komodor

**Homepage:** <https://github.com/davidcollom/komodor-security-reporter>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| David Collom | <david@collom.co.uk> |  |

## Source Code

* <https://github.com/davidcollom/komodor-security-reporter>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Pod affinity/anti-affinity rules. @param affinity Affinity rules. |
| config.clusterName | string | `"cluster-1"` | Cluster name included in emitted events. @param config.clusterName Cluster identifier used in event metadata. |
| config.komodor.baseURL | string | `"https://api.komodor.io"` | Komodor API base URL. @param config.komodor.baseURL Base URL for Komodor API. |
| config.namespaces.exclude | list | this should be a list of namespaces or empty to exclude no namespaces. | Namespaces to exclude from reconciliation. @param config.namespaces.exclude Namespaces to exclude. |
| config.namespaces.include | list | this should be a list of namespaces or empty to include all namespaces. | Namespaces to include in reconciliation. @param config.namespaces.include Namespaces to include. |
| config.publishing.dedupeTTL | string | `"24h"` | Deduplication TTL for repeated findings. @param config.publishing.dedupeTTL Deduplication time window. |
| config.publishing.includeTopFindings | int | `5` | Number of top findings to include in payloads. @param config.publishing.includeTopFindings Number of top findings to include. |
| config.publishing.minimumSeverity | string | `"high"` | Minimum severity required before publishing findings. @param config.publishing.minimumSeverity Minimum severity threshold. |
| config.publishing.mode | string | `"komodor"` | Publishing mode (`komodor`, `events`, or `both`). @param config.publishing.mode Destination(s) for published findings. |
| config.publishing.publishCleanScans | bool | `false` | Publish clean scans with no findings. @param config.publishing.publishCleanScans Whether to publish clean scan results. |
| config.registry.resolveDigest | bool | `true` | Resolve image tags to immutable digests. @param config.registry.resolveDigest Whether to resolve image digests. |
| config.scanners.concurrency | int | `4` | Scanner definitions. @param config.scanners.scanners List of scanner configurations. @param config.scanners.concurrency Scanner concurrency. |
| config.scanners.scanners[0].enabled | bool | `true` |  |
| config.scanners.scanners[0].name | string | `"trivyoperator"` |  |
| config.scanners.scanners[0].resources[0] | string | `"vulnerabilityreports"` |  |
| config.scanners.scanners[0].type | string | `"trivy-operator"` |  |
| config.workloads.kinds | list | `["Deployment","StatefulSet","DaemonSet","Job","CronJob"]` | Workload kinds to scan. @param config.workloads.kinds Kubernetes workload kinds to watch. |
| fullnameOverride | string | `""` | Fully override the generated release name. @param fullnameOverride String to fully override the release name. |
| image.pullPolicy | string | `"IfNotPresent"` | Container image pull policy. @param image.pullPolicy Kubernetes image pull policy. |
| image.repository | string | `"ghcr.io/davidcollom/komodor-security-reporter"` | Container image repository. @param image.repository Image repository for the reporter container. |
| image.tag | string | `"latest"` | Container image tag. @param image.tag Image tag to deploy. |
| imagePullSecrets | list | `[]` | List of image pull secrets for private registries. @param imagePullSecrets List of imagePullSecrets to attach to the pod. |
| komodor.apiKey | string | `""` | Komodor API key value used when `komodor.createSecret=true`. @param komodor.apiKey Komodor API key to store in a created Secret. |
| komodor.createSecret | bool | `false` | Create a Secret containing the Komodor API key. @param komodor.createSecret Whether to create a Komodor credentials Secret. |
| komodor.secretName | string | `"komodor-credentials"` | Existing Secret name containing `api-key`. @param komodor.secretName Name of the Secret containing Komodor API key. |
| livenessProbe | object | `{"failureThreshold":3,"httpGet":{"path":"/healthz","port":"metrics"},"initialDelaySeconds":30,"periodSeconds":10,"timeoutSeconds":1}` | Full liveness probe definition. Set to null to disable the liveness probe. @param livenessProbe Kubernetes livenessProbe map. |
| logging.level | string | `"info"` | Application log level. @param logging.level Log level (`debug`, `info`, `warn`, `error`). |
| metrics.enabled | bool | `true` | Enable metrics endpoint. @param metrics.enabled Whether metrics endpoint is enabled. |
| metrics.port | int | `8080` | Metrics and health endpoint port. @param metrics.port Container port for metrics/health endpoints. |
| nameOverride | string | `""` | Override the name of the chart. @param nameOverride String to partially override the release name. |
| nodeSelector | object | `{}` | Node selector labels for pod scheduling. @param nodeSelector Node selector map. |
| persistence.enabled | bool | `true` | Enable persistence for local cache/state. @param persistence.enabled Whether persistence is enabled. |
| persistence.existingClaim | string | `""` | Existing PersistentVolumeClaim to use instead of creating one. @param persistence.existingClaim Existing PVC name. |
| persistence.size | string | `"1Gi"` | PVC requested storage size. @param persistence.size PersistentVolumeClaim size. |
| persistence.storageClassName | string | `""` | StorageClass name for the PVC. @param persistence.storageClassName StorageClass name for PVC. |
| podAnnotations | object | `{}` | Extra annotations to add to the pod template. @param podAnnotations Additional pod annotations. |
| podSecurityContext | object | `{"runAsNonRoot":true,"runAsUser":65534}` | Pod-level security context. @param podSecurityContext Pod security context values. |
| rbac.create | bool | `true` | Create RBAC resources. @param rbac.create Whether to create RBAC resources. |
| rbac.scope | string | `"cluster"` | RBAC scope (`cluster` or `namespace`). @param rbac.scope Scope of RBAC permissions. |
| readinessProbe | object | `{"failureThreshold":3,"httpGet":{"path":"/readyz","port":"metrics"},"initialDelaySeconds":10,"periodSeconds":5,"successThreshold":1,"timeoutSeconds":1}` | Full readiness probe definition. Set to null to disable the readiness probe. @param readinessProbe Kubernetes readinessProbe map. |
| replicaCount | int | `1` | Number of replicas for the Deployment. @param replicaCount Number of pod replicas to run. |
| resources | object | `{"limits":{"cpu":"500m","memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}` | Pod resource requests and limits. @param resources CPU and memory requests/limits. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":65534}` | Container-level security context. @param securityContext Container security context values. |
| service.port | int | `8080` | Service port for metrics/health endpoint. @param service.port Service port. |
| service.targetPort | int | `8080` | Target container port for the service. @param service.targetPort Target container port. |
| service.type | string | `"ClusterIP"` | Kubernetes Service type. @param service.type Service type. |
| serviceAccount.annotations | object | `{}` | Annotations for the ServiceAccount. @param serviceAccount.annotations Additional ServiceAccount annotations. |
| serviceAccount.create | bool | `true` | Create a dedicated ServiceAccount. @param serviceAccount.create Whether to create a ServiceAccount resource. |
| serviceAccount.name | string | `""` | Use an existing ServiceAccount name. @param serviceAccount.name Existing ServiceAccount name to use. |
| tolerations | list | `[]` | Pod tolerations. @param tolerations List of tolerations. |

