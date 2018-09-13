package yaccZonefileParser

import (
	"bufio"
	"bytes"
	"errors"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
)

func init() {
	/*h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(h)*/
}

//Parser can be used to parse RAINS zone files
type Parser struct{}

//Encode returns the given section represented in the zone file format if it is a zoneSection.
//In all other cases it returns the section in a displayable format similar to the zone file format
func (p Parser) Encode(s rainslib.MessageSection) string {
	return zoneFileParser.GetEncoding(s, false)
}

//Decode returns all assertions contained in the given zonefile
func (p Parser) Decode(zoneFile []byte) ([]*rainslib.AssertionSection, error) {
	log.Error("Not yet supported")
	return nil, nil
}

//DecodeZone returns a zone exactly as it is represented in the zonefile
func (p Parser) DecodeZone(zoneFile []byte) (*rainslib.ZoneSection, error) {
	lines := removeComments(bufio.NewScanner(bytes.NewReader(zoneFile)))
	log.Debug("Preprocessed input", "data", lines)
	parser := ZFPNewParser()
	parser.Parse(&ZFPLex{lines: lines})
	zone, ok := parser.Result()[0].(*rainslib.ZoneSection)
	if !ok {
		return nil, errors.New("First element of zonefile is not a zone. (Note, only the first element of the zonefile is considered)")
	}
	return zone, nil
}
