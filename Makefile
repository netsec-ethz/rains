COMMIT=$(shell git rev-parse HEAD)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
HOSTNAME=$(shell hostname -f)

BUILD_PATH=${PWD}/build/

LDFLAGS = -ldflags "-X main.buildinfo_hostname=${HOSTNAME} -X main.buildinfo_commit=${COMMIT} -X main.buildinfo_branch=${BRANCH}"

all: clean rainsd zonepub rdig keymanager

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

vet:
	go fmt ./...
	go vet ./internal/...
	go vet ./cmd/...
	go vet ./test/...

generate: internal/pkg/zonefile/zoneFileParser.go go_generate

internal/pkg/zonefile/zoneFileParser.go: internal/pkg/zonefile/zoneFileParser.y
	$(if $(which goyacc), go install golang.org/x/tools/cmd/goyacc)
	goyacc -p "ZFP" -o $@ $<

go_generate:
	$(if $(which stringer), go install golang.org/x/tools/cmd/stringer)
	# XXX: not running github.com/campoy/jsonenums as its currently broken with modules!
	go generate -run stringer ./...

test: vet unit integration

unit:
	go test ./internal/pkg/...

integration: rainsd rdig zonepub
	go test -v -tags=integration ./test/integration/

cover:
	go test -coverprofile=coverage.out -coverpkg=./internal/pkg/... ./internal/pkg/... ./test/...
	go tool cover -html=coverage.out -o coverage.html
	firefox coverage.html

.PHONY: all clean rainsd zonepub rdig zoneman keymanager vet generate go_generate test unit integration
