FROM --platform=${BUILDPLATFORM} golang:bullseye as builder

WORKDIR /build
COPY . .
ENV CGO_ENABLED=0
ARG TARGETOS TARGETARCH
RUN  --mount=type=cache,target=/go/pkg/mod \
     --mount=type=cache,target=/root/.cache/go-build \
     GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o gcp-auditor .

FROM alpine:3.17
RUN apk add --no-cache git ca-certificates \
    && rm -rf /var/cache/apk/* && \
    update-ca-certificates
COPY --from=builder /build/gcp-auditor /usr/bin/gcp-auditor
ENTRYPOINT ["/usr/bin/gcp-auditor"]
