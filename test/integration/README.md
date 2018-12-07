# README

## Queries
The queries and expected answers are stored in a file located at 'testdata/messages/messages.txt'.
The query must be on a single line. The answer sections must be on the following line(s). An empty
line marks the end of the answer. Queries are represented in a zonefile like format and answers are
represented in zonefile format.

## Coverage
The file fullCoverageTCP.go must be present and include all paths for which we want to do coverage
measurements. Otherwise the coverage tool does not add instrumentation code to these packages.

To create coverage measurements execute the following commands:
- go test -coverprofile=coverage.out -coverpkg=../../internal/pkg/...
- go tool cover -html=coverage.out -o coverage.html
- firefox coverage.html