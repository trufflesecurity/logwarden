.PHONY: run fmt

run:
	go run . --project truffle-audit --subscription gcp-auditor-test

fmt:
	opa fmt policy/*/*.rego -w

lint:
	golangci-lint run --enable bodyclose --enable exportloopref --out-format=colored-line-number --timeout 10m