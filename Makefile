verbosity := 0

clean: ## Remove previous builds
	@rm -rf data bin/gosop

install-linters:
	go install -u golang.org/x/lint/golint
	go install github.com/golangci/golangci-lint/cmd/golangci-lint

lint:
	golint -set_exit_status ./... && golangci-lint run ./...

test:  ## Run example script
	bash scripts/tests.sh gosop -v $(verbosity) rfc4880
	bash scripts/tests.sh gosop -v $(verbosity) draft-koch-openpgp
	bash scripts/tests.sh gosop -v $(verbosity) draft-ietf-openpgp-crypto-refresh
