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
| affinity | object | `{}` |  |
| config.clusterName | string | `"cluster-1"` |  |
| config.komodor.baseURL | string | `"https://app.komodor.io"` |  |
| config.komodor.enabled | bool | `true` |  |
| config.namespaces.exclude[0] | string | `"kube-system"` |  |
| config.namespaces.exclude[1] | string | `"kube-node-lease"` |  |
| config.namespaces.include[0] | string | `"production"` |  |
| config.namespaces.include[1] | string | `"platform"` |  |
| config.publishing.dedupeTTL | string | `"24h"` |  |
| config.publishing.includeTopFindings | int | `5` |  |
| config.publishing.minimumSeverity | string | `"high"` |  |
| config.publishing.mode | string | `"komodor"` |  |
| config.publishing.publishCleanScans | bool | `false` |  |
| config.registry.resolveDigest | bool | `true` |  |
| config.scanners.scanners[0].command.binary | string | `"/usr/local/bin/trivy"` |  |
| config.scanners.scanners[0].command.timeout | string | `"5m"` |  |
| config.scanners.scanners[0].enabled | bool | `true` |  |
| config.scanners.scanners[0].name | string | `"trivy"` |  |
| config.scanners.scanners[0].type | string | `"trivy"` |  |
| config.workloads.kinds[0] | string | `"Deployment"` |  |
| config.workloads.kinds[1] | string | `"StatefulSet"` |  |
| config.workloads.kinds[2] | string | `"DaemonSet"` |  |
| config.workloads.kinds[3] | string | `"Job"` |  |
| config.workloads.kinds[4] | string | `"CronJob"` |  |
| fullnameOverride | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"ghcr.io/davidcollom/komodor-security-reporter"` |  |
| image.tag | string | `"latest"` |  |
| imagePullSecrets | list | `[]` |  |
| komodor.createSecret | bool | `false` |  |
| komodor.secretName | string | `"komodor-credentials"` |  |
| logging.level | string | `"info"` |  |
| metrics.enabled | bool | `true` |  |
| metrics.port | int | `8080` |  |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` |  |
| persistence.enabled | bool | `true` |  |
| persistence.existingClaim | string | `""` |  |
| persistence.size | string | `"1Gi"` |  |
| persistence.storageClassName | string | `""` |  |
| podAnnotations | object | `{}` |  |
| podSecurityContext.allowPrivilegeEscalation | bool | `false` |  |
| podSecurityContext.capabilities.drop[0] | string | `"ALL"` |  |
| podSecurityContext.readOnlyRootFilesystem | bool | `true` |  |
| podSecurityContext.runAsNonRoot | bool | `true` |  |
| podSecurityContext.runAsUser | int | `65534` |  |
| rbac.create | bool | `true` |  |
| rbac.scope | string | `"cluster"` |  |
| replicaCount | int | `1` |  |
| resources.limits.cpu | string | `"500m"` |  |
| resources.limits.memory | string | `"512Mi"` |  |
| resources.requests.cpu | string | `"100m"` |  |
| resources.requests.memory | string | `"128Mi"` |  |
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.capabilities.drop[0] | string | `"ALL"` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| securityContext.runAsNonRoot | bool | `true` |  |
| securityContext.runAsUser | int | `65534` |  |
| service.port | int | `8080` |  |
| service.targetPort | int | `8080` |  |
| service.type | string | `"ClusterIP"` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| tolerations | list | `[]` |  |

