COMMIT=$(shell git rev-parse HEAD)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
HOSTNAME=$(shell hostname -f)

BUILD_PATH=${PWD}/build/

LDFLAGS = -ldflags "-X main.buildinfo_hostname=${HOSTNAME} -X main.buildinfo_commit=${COMMIT} -X main.buildinfo_branch=${BRANCH}"

all: clean rainsd rainsd zonepub rdig keymanager

clean:
	rm -rf ${BUILD_PATH}
	mkdir ${BUILD_PATH}

rainsd:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o rainsd github.com/netsec-ethz/rains/cmd/rainsd ; \
	cd - >/dev/null

zonepub:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o publisher github.com/netsec-ethz/rains/cmd/zonepub ; \
	cd - >/dev/null

rdig:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o rdig github.com/netsec-ethz/rains/cmd/rdig ; \
	cd - >/dev/null

keymanager:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o keymanager github.com/netsec-ethz/rains/cmd/keyManager ;\
	cd - >/dev/null

tests:
	go fmt ./...
	go vet ./internal/...
	go vet ./cmd/...
	go vet ./test/...
	go test ./internal/pkg/...
	go test -v ./test/integration/

cover:
	go test -coverprofile=coverage.out -coverpkg=./internal/pkg/... ./internal/pkg/... ./test/...
	go tool cover -html=coverage.out -o coverage.html
	firefox coverage.html

.PHONY: clean rainsd zonepub rdig zoneman keymanager
