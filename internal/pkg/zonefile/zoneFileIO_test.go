package zonefile

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/section"
)

func TestEncodeDecodeZone(t *testing.T) {
	zone, err := IO{}.LoadZonefile("test/zonefile.txt")
	if err != nil {
		t.Error(err)
	}
	sections := []section.Section{}
	for _, e := range zone {
		sections = append(sections, e)
	}
	err = IO{}.EncodeAndStore("test/newzonefile.txt", sections)
	origData, _ := ioutil.ReadFile("test/zonefile.txt")
	newData, _ := ioutil.ReadFile("test/newzonefile.txt")
	scanner1 := bufio.NewScanner(bytes.NewReader(origData))
	scanner2 := bufio.NewScanner(bytes.NewReader(newData))
	scanner1.Split(bufio.ScanWords)
	scanner2.Split(bufio.ScanWords)
	go1 := scanner1.Scan()
	go2 := scanner2.Scan()
	if go1 != go2 {
		t.Error("One file has more content")
	}
	for go1 {
		if scanner1.Text() != scanner2.Text() {
			t.Error("Content is different at token level", "a=", scanner1.Text(), "b=", scanner2.Text())
		}
		go1 = scanner1.Scan()
		go2 = scanner2.Scan()
		if go1 != go2 {
			t.Error("One file has more content")
		}
	}

	// Check reencoding single assertions works
	scanner3 := bufio.NewScanner(bytes.NewReader(origData))
	scanner4 := bufio.NewScanner(bytes.NewReader(newData))
	scanner3.Split(bufio.ScanLines)
	scanner4.Split(bufio.ScanLines)
	go3 := scanner3.Scan()
	go4 := scanner4.Scan()
	var next string
	if go3 != go4 {
		t.Error("One file has more lines")
	}
	for go3 {
		if scanner3.Text() != scanner4.Text() {
			t.Error("Content is different at line level", scanner3.Text(), scanner4.Text())
		}
		next = scanner3.Text()
		go3 = scanner3.Scan()
		go4 = scanner4.Scan()
		if go3 != go4 {
			t.Error("One file has more lines")
		}
	}

	decodedSection := decode(t, []byte(next))[0]
	stringSection := strings.TrimSpace(IO{}.Encode([]section.Section{decodedSection}))
	if next != stringSection {
		t.Error(fmt.Sprintf("Content is different:\nExpected:\t'%v'\nGot:\t\t'%v'", next, stringSection))
	}
}

func decode(t *testing.T, input []byte) []section.WithSigForward {
	zfParser := IO{}
	sections, err := zfParser.Decode(input)
	if err != nil {
		t.Error(fmt.Sprintf("Was not able to parse section: %v", err))
	}
	return sections
}
