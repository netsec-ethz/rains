package main

import (
	"fmt"
	"os"
	"rains/proto"
	"rains/rainslib"

	capnp "zombiezen.com/go/capnproto2"
)

func main() {
	o := rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}
	a := rainslib.AssertionSection{Content: []rainslib.Object{o}, Context: ".", SubjectName: "ethz", SubjectZone: "ch"}
	m := rainslib.RainsMessage{Content: []rainslib.MessageSection{a}, Token: rainslib.GenerateToken()}

	//
	//Encode RAINS Message
	//
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		panic(err)
	}

	message, err := proto.NewRootRainsMessage(seg)
	if err != nil {
		panic(err)
	}
	tok := [16]byte(m.Token)
	message.SetToken(tok[:])
	fmt.Println(tok)
	//FIXME CFE use a switch statement
	obj, err := proto.NewObj(seg)
	obj.SetType(proto.ObjectType_oTIP4Addr)
	obj.Value().SetIp4(a.Content[0].Value.(string))
	objList, err := proto.NewObj_List(seg, int32(len(a.Content)))
	objList.Set(0, obj)
	assertion, err := proto.NewAssertionSection(seg)
	assertion.SetContent(objList)
	assertion.SetContext(a.Context)
	assertion.SetSubjectName(a.SubjectName)
	assertion.SetSubjectZone(a.SubjectZone)
	section, err := proto.NewMessageSection(seg)
	section.SetAssertion(assertion)
	sectionList, err := proto.NewMessageSection_List(seg, int32(len(m.Content)))
	sectionList.Set(0, section)
	message.SetContent(sectionList)

	//
	// Write the message to file.
	//
	file, err := os.Create("tmp/test.enc")
	if err != nil {
		fmt.Println("BAD ERROR")
	}

	err = capnp.NewEncoder(file).Encode(msg)
	if err != nil {
		panic(err)
	}

	//
	//READ message from file
	//
	file2, err := os.Open("tmp/test.enc")
	if err != nil {
		fmt.Println("BADERROR2")
	}
	input, err := capnp.NewDecoder(file2).Decode()
	if err != nil {
		panic(err)
	}

	//
	// Decode Rains Message
	//
	rootRainsMsg, err := proto.ReadRootRainsMessage(input)
	if err != nil {
		panic(err)
	}

	inputToken, _ := rootRainsMsg.Token()
	fmt.Println(inputToken)
	inputSecList, _ := rootRainsMsg.Content()
	inputSection := inputSecList.At(0)
	switch inputSection.Which() {
	case proto.MessageSection_Which_assertion:
		inputAssertion, _ := inputSection.Assertion()
		fmt.Println(inputAssertion.Context())
		fmt.Println(inputAssertion.SubjectName())
		fmt.Println(inputAssertion.SubjectZone())
	}
}
