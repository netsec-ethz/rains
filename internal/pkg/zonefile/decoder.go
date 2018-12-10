package zonefile

import (
	"bufio"
	"strconv"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
)

//decodeNameQueryUnsafe returns a name query. It assumes the encoding is in the correct format and
//does not perform input validation
func decodeNameQueryUnsafe(scanner *bufio.Scanner) *query.Name {
	scanner.Scan()
	q := &query.Name{}
	q.Context = scanner.Text()
	scanner.Scan()
	q.Name = scanner.Text()
	scanner.Scan()
	q.Types = decodeObjectTypesUnsafe(scanner)
	scanner.Scan()
	q.Expiration, _ = strconv.ParseInt(scanner.Text(), 10, 64)
	scanner.Scan()
	q.Options = decodeQueryOptionsUnsafe(scanner)
	return q
}

//decodeObjectTypesUnsafe returns query connection. It assumes the encoding is in the correct format
//and does not perform input validation
func decodeObjectTypesUnsafe(scanner *bufio.Scanner) []object.Type {
	types := []object.Type{}
	scanner.Scan()
	for scanner.Text() != "]" {
		val, _ := strconv.Atoi(scanner.Text())
		types = append(types, object.Type(val))
		scanner.Scan()
	}
	return types
}

//decodeQueryOptionsUnsafe returns query options. It assumes the encoding is in the correct format
//and does not perform input validation
func decodeQueryOptionsUnsafe(scanner *bufio.Scanner) []query.Option {
	options := []query.Option{}
	scanner.Scan()
	for scanner.Text() != "]" {
		val, _ := strconv.Atoi(scanner.Text())
		options = append(options, query.Option(val))
		scanner.Scan()
	}
	return options
}
