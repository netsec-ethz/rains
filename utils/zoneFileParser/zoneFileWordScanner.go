package zoneFileParser

import (
	"bufio"
	"bytes"
	"strings"
)

//NewWordScanner returns a WordScanner
func NewWordScanner(data []byte) *WordScanner {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(bufio.ScanWords)
	return &WordScanner{data: data, scanner: scanner, wordsRead: 0}
}

//WordScanner uses bufio.Scanner to scan words of the input. Additionally it keeps track of the line (of the input) on which the scanner currently is
type WordScanner struct {
	data      []byte
	scanner   *bufio.Scanner
	wordsRead int
}

//Scan moves the pointer to the next token of the scan
func (ws *WordScanner) Scan() bool {
	ws.wordsRead++
	return ws.scanner.Scan()
}

//Text returns the value of the current Token as a string
func (ws *WordScanner) Text() string {
	return ws.scanner.Text()
}

//LineNumber returns the linenumber of the input data where the token pointer of the scanner currently is.
func (ws *WordScanner) LineNumber() int {
	lineScanner := bufio.NewScanner(bytes.NewReader(ws.data))
	i := 0
	lineNr := 1
	for lineScanner.Scan() && i < ws.wordsRead {
		scanner := bufio.NewScanner(strings.NewReader(lineScanner.Text()))
		scanner.Split(bufio.ScanWords)
		for scanner.Scan() {
			i++
			if i == ws.wordsRead {
				return lineNr
			}
		}
		lineNr++
	}
	return lineNr
}
