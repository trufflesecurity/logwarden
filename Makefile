.PHONY: run eval fmt test

run:
	go run . --project truffle-audit --subscription logwarden-test

eval:
	go run . eval --policies policy/gcp testdata/events.ndjson

test:
	go test ./...
	opa test policy policy_test

fmt:
	opa fmt -w policy/

lint:
	golangci-lint run --enable bodyclose --timeout 10m

docker:
	docker buildx build --push \
		--platform linux/amd64,linux/arm64 \
		--tag us-docker.pkg.dev/thog-artifacts/public/logwarden:latest .
