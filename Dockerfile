FROM alpine:3.17

RUN apk add --no-cache git ca-certificates \
    && rm -rf /var/cache/apk/* && \
    update-ca-certificates
WORKDIR /usr/bin/
COPY gcp-auditor .
ENTRYPOINT ["/usr/bin/gcp-auditor"]
