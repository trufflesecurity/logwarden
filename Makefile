.PHONY: run fmt

run:
	go run . --project truffle-audit --subscription logwarden-test

fmt:
	opa fmt policy/*/*.rego -w

lint:
	golangci-lint run --enable bodyclose --enable exportloopref --out-format=colored-line-number --timeout 10m

docker:
	docker buildx build --push \
		--platform linux/amd64,linux/arm64 \
		--tag us-docker.pkg.dev/thog-artifacts/public/logwarden:latest .