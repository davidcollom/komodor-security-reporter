FROM alpine:3.23

ARG TARGETPLATFORM

RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -S watcher && \
    adduser -S -D -H -u 10001 -G watcher watcher

WORKDIR /

# Binary is expected to be provided by GoReleaser docker builds in linux/$TARGETARCH/.
COPY ${TARGETPLATFORM}/komodor-security-reporter /usr/local/bin/komodor-security-reporter

# Optionally install Trivy if it should be bundled
# RUN apk add --no-cache trivy

USER watcher

EXPOSE 8080

ENTRYPOINT ["komodor-security-reporter"]
