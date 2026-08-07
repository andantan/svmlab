PROJECT = svmlab

BIN_DIR = bin

GO_DIR = ipx
GO_SERVER_BIN = server

.PHONY: help \
	go-build go-build-server server \
	swag go-test fmt vet tidy \
	clean

help:
	@echo "$(PROJECT) commands:"
	@echo ""
	@echo "  make go-build          Build all Go binaries"
	@echo "  make go-build-server   Build server binary"
	@echo "  make server            Regenerate docs, build, and run the API server"
	@echo ""
	@echo "  make swag              Regenerate Swagger docs"
	@echo "  make go-test           Run Go tests"
	@echo "  make fmt               Format Go sources"
	@echo "  make vet               Run go vet"
	@echo "  make tidy              Tidy go.mod and go.sum"
	@echo ""
	@echo "  make clean             Remove generated build outputs"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

go-build-server: $(BIN_DIR)
	cd $(GO_DIR) && go build -o ../$(BIN_DIR)/$(GO_SERVER_BIN) ./cmd/server

go-build: go-build-server

# swag runs first: the generated docs package is compiled into the binary, so
# building before regenerating would serve the previous run's spec.
server: swag go-build-server
	./$(BIN_DIR)/$(GO_SERVER_BIN)

swag:
	cd $(GO_DIR) && swag init -g cmd/server/main.go -o docs

go-test:
	cd $(GO_DIR) && go test ./...

fmt:
	cd $(GO_DIR) && gofmt -w .

vet:
	cd $(GO_DIR) && go vet ./...

tidy:
	cd $(GO_DIR) && go mod tidy

clean:
	rm -rf $(BIN_DIR)
