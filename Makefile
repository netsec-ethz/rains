COMMIT=$(shell git rev-parse HEAD)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
HOSTNAME=$(shell hostname -f)

BUILD_PATH=${GOPATH}/src/github.com/netsec-ethz/rains/build/

LDFLAGS = -ldflags "-X main.buildinfo_hostname=${HOSTNAME} -X main.buildinfo_commit=${COMMIT} -X main.buildinfo_branch=${BRANCH}"

all: clean rainsd rainspub rainsdig

clean:
	rm -rf ${BUILD_PATH}
	mkdir ${BUILD_PATH}

rainsd:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o rainsd github.com/netsec-ethz/rains/example/server ; \
	cd - >/dev/null

rainspub:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o rainspub github.com/netsec-ethz/rains/example/pub ; \
	cd - >/dev/null

rainsdig:
	cd ${BUILD_PATH}; \
	go build ${LDFLAGS} -o rainsdig github.com/netsec-ethz/rains/rainsdig ; \
	cd - >/dev/null

.PHONY: clean rainsd rainspub rainsdig
