BINARY_NAME=spiffe-client

all: spiffe-client

stripped: spiffe-client-stripped

static: spiffe-client-static

static-and-stripped: spiffe-client-static-and-stripped

spiffe-client:
	GOARCH=amd64 GOOS=linux go build -o ./bin/${BINARY_NAME} ./cmd/${BINARY_NAME}

spiffe-client-stripped:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=1 go build -ldflags '-s' -o ./bin/${BINARY_NAME} ./cmd/${BINARY_NAME}

spiffe-client-static:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o ./bin/${BINARY_NAME} ./cmd/${BINARY_NAME}

spiffe-client-static-and-stripped:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -ldflags '-s' -o ./bin/${BINARY_NAME} ./cmd/${BINARY_NAME}

.PHONY: image run build_and_run dep vet

image:
	docker build -t spiffe-client .

run:
	./${BINARY_NAME}

build_and_run: build run

clean:
	go clean
	rm ./bin/${BINARY_NAME}

dep:
	go mod download

vet:
	go vet

