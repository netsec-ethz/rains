package zonefile

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"strings"
	"testing"
)

func TestEncodeDecodeZone(t *testing.T) {
	data, err := ioutil.ReadFile("test/zonefile.txt")
	if err != nil {
		t.Error(err)
	}
	parser := IO{}
	zone, err := parser.Decode(data)
	if err != nil {
		t.Error(err)
	}
	encoding := parser.EncodeSection(zone[0])
	err = ioutil.WriteFile("test/newzonefile.txt", []byte(encoding), 0600)
	if err != nil {
		t.Error(err)
	}
	scanner1 := bufio.NewScanner(bytes.NewReader(data))
	scanner2 := bufio.NewScanner(strings.NewReader(encoding))
	scanner1.Split(bufio.ScanWords)
	scanner2.Split(bufio.ScanWords)
	go1 := scanner1.Scan()
	go2 := scanner2.Scan()
	if go1 != go2 {
		t.Error("One file has more content")
	}
	for go1 {
		if scanner1.Text() != scanner2.Text() {
			t.Error("Content is different", scanner1.Text(), scanner2.Text())
		}
		go1 = scanner1.Scan()
		go2 = scanner2.Scan()
		if go1 != go2 {
			t.Error("One file has more content")
		}
	}
}
