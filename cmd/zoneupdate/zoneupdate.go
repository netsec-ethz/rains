package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

func main() {

	flag.Usage = func() {
		fmt.Println("This tool adds assertions to a zonefile and ensures sorted order")
		flag.PrintDefaults()
	}

	// flags
	file := flag.String("zf", "zonefile.txt", "Path to zonefile")
	name := flag.String("n", "", "name which is added to zonefile")
	t := flag.String("t", "", "the type of the record being added")
	value := flag.String("v", "", "value being added to zonefile")

	flag.Parse()

	if *name == "" || *value == "" {
		log.Fatal("Error: name and value cannot be empty")
	}

	ts, err := object.ParseTypes(*t)
	if err != nil || len(ts) != 1 {
		log.Fatal("please provide a single, valid type")
	}

	zone, err := zonefile.IO{}.LoadZonefile(*file)
	if err != nil {
		log.Fatal(err)
	}
	sections := []section.Section{}
	for _, e := range zone {
		sections = append(sections, e)
	}
	if len(sections) < 1 {
		log.Fatal("No zone found")
	}
	z, ok := sections[0].(*section.Zone)
	if !ok {
		log.Fatal("No zone found")
	}

	obj := object.Object{Type: ts[0], Value: *value}
	assertions := []*section.Assertion{}
	added := false
	for _, e := range z.Content {
		if e.SubjectName != *name {
			assertions = append(assertions, e)
		} else {
			// assertion for name exists
			objs := []object.Object{}
			for _, o := range e.Content {
				if o.Type != ts[0] {
					objs = append(objs, o)
				} else {
					// update the object to the new value
					objs = append(objs, obj)
					added = true
				}
			}
			if !added {
				objs = append(objs, obj)
				added = true
			}
			a := section.Assertion{SubjectName: e.SubjectName, Content: objs}
			a.Sort()
			assertions = append(assertions, &a)
		}
	}

	if !added {
		a := section.Assertion{SubjectName: *name, Content: []object.Object{obj}}
		assertions = append(assertions, &a)
	}

	z.Content = assertions
	z.Sort()
	zonefile.IO{}.EncodeAndStore(*file, sections)
}
