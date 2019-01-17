package zonefile

import (
	"bufio"
	"bytes"
	"io/ioutil"
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
			t.Error("Content is different", scanner1.Text(), scanner2.Text())
		}
		go1 = scanner1.Scan()
		go2 = scanner2.Scan()
		if go1 != go2 {
			t.Error("One file has more content")
		}
	}
}
