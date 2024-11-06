default: build

test:
	go test ./... -cover -coverprofile=coverage.txt

build:
	go build

install: build
	mkdir -p ~/.tflint.d/plugins
	mv ./tflint-ruleset-azurerm-security ~/.tflint.d/plugins

lint:
	golint --set_exit_status $$(go list ./...)
	go vet ./...
	
tools:
	go install golang.org/x/lint/golint@latest