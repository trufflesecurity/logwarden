.PHONY: run fmt

run:
	go run . --project truffle-audit --subscription gcp-auditor-test

fmt:
	opa fmt policy/*/*.rego -w
