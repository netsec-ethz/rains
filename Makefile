COMMIT=$(shell git rev-parse HEAD)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
HOSTNAME=$(shell hostname -f)

BUILD_PATH=${PWD}/build/

LDFLAGS = -ldflags "-X main.buildinfo_hostname=${HOSTNAME} -X main.buildinfo_commit=${COMMIT} -X main.buildinfo_branch=${BRANCH}"

all: clean rainsd rainsd zonepub rdig keymanager

clean:
	rm -rf ${BUILD_PATH}
	mkdir ${BUILD_PATH}

rainsd: vet
	go build ${LDFLAGS} -o ${BUILD_PATH}/rainsd github.com/netsec-ethz/rains/cmd/rainsd

zonepub: vet
	go build ${LDFLAGS} -o ${BUILD_PATH}/publisher github.com/netsec-ethz/rains/cmd/zonepub

rdig: vet
	go build ${LDFLAGS} -o ${BUILD_PATH}/rdig github.com/netsec-ethz/rains/cmd/rdig

keymanager: vet
	go build ${LDFLAGS} -o ${BUILD_PATH}/keymanager github.com/netsec-ethz/rains/cmd/keyManager


test: vet unit integration

vet:
	go fmt ./...
	go vet ./internal/...
	go vet ./cmd/...
	go vet ./test/...

unit:
	go test ./internal/pkg/...

integration: rainsd rdig zonepub
	go test -v -tags=integration ./test/integration/

cover:
	go test -coverprofile=coverage.out -coverpkg=./internal/pkg/... ./internal/pkg/... ./test/...
	go tool cover -html=coverage.out -o coverage.html
	firefox coverage.html

.PHONY: clean rainsd zonepub rdig zoneman keymanager vet unit integration
