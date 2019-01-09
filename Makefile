COMMIT=$(shell git rev-parse HEAD)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
HOSTNAME=$(shell hostname -f)

BUILD_PATH=${PWD}/build/

LDFLAGS = -ldflags "-X main.buildinfo_hostname=${HOSTNAME} -X main.buildinfo_commit=${COMMIT} -X main.buildinfo_branch=${BRANCH}"

all: clean rainsd rainsd zonepub rainsdig zoneman resolve

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

rainsdig:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o rainsdig github.com/netsec-ethz/rains/cmd/rainsdig ; \
	cd - >/dev/null

zoneman:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o zoneman github.com/netsec-ethz/rains/cmd/zoneManager ;\
	cd - >/dev/null

resolve:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o resolve github.com/netsec-ethz/rains/cmd/resolve ; \
	cd - >/dev/null

tests:
	go fmt ./...
	go vet ./internal/...
	go vet ./examples/...
	go vet ./cmd/...
	go vet ./test/...
	go test ./internal/pkg/...
	go test -v ./test/integration/

.PHONY: clean rainsd zonepub rainsdig zoneman resolve
