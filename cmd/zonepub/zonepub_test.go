package main

//TODO CFE fix tests
/*func TestInitRainspub(t *testing.T) {
	var tests = []struct {
		input  string
		errMsg string
	}{
		{"test/rainspub.conf", ""},
		{"wrongPath/rainspub.conf", "open wrongPath/rainspub.conf: no such file or directory"},       //trigger error
		{"test/rainspubWrongPath.conf", "open WrongPath/zonePrivate.key: no such file or directory"}, //trigger error
	}
	for i, test := range tests {
		err := Init(test.input)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: InitRainspub() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil {
			if parser == nil || msgParser == nil {
				t.Errorf("%d: parser should not be nil.", i)
			}
		}
	}
}

func TestPublishInformation(t *testing.T) {
	var tests = []struct {
		input  string
		errMsg string
	}{
		{"test/rainspub2.conf", ""},                                                        //no errors
		{"test/rainspub.conf", "open zoneFiles/chZoneFile.txt: no such file or directory"}, //load assertion error
	}
	for i, test := range tests {
		Init(test.input)
		err := publishZone(nil, 0)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: PublishInformation() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
	}
}

func TestCreateRainsMessage(t *testing.T) {
	Init("test/rainspub.conf")
	a := getAssertionWithTwoIPObjects()
	var tests = []struct {
		input  *rainslib.ZoneSection
		errMsg string
	}{
		{&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
			&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
				Content: []*rainslib.AssertionSection{a}}}}, ""},
		{&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{new(rainslib.ZoneSection)}},
			"Unsupported section type"},
	}
	for i, test := range tests {
		msg, err := createRainsMessage(test.input)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: signZone() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil {
			if _, err := msgParser.Decode(msg); err != nil {
				t.Errorf("%d: createRainsMessage() did not generate a valid encoding.", i)
			}
		}
	}
}

func TestLoadConfig(t *testing.T) {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:5022")
	tcpAddr2, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:5023")
	expectedConfig := zonepubConfig{
		AssertionValidUntil:  86400 * time.Hour,
		DelegationValidUntil: 86439 * time.Hour,
		ShardValidUntil:      86400 * time.Hour,
		ZoneValidUntil:       86400 * time.Hour,
		AssertionValidSince:  0,
		DelegationValidSince: -1 * time.Hour,
		ShardValidSince:      0,
		ZoneValidSince:       0,
		ServerAddresses: []rainslib.ConnInfo{
			rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr},
			rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr2},
		},
		ZoneFilePath:       "zoneFiles/chZoneFile.txt",
		ZonePrivateKeyPath: []string{"test/zonePrivate.key"},
	}
	var tests = []struct {
		input  string
		errMsg string
	}{
		{"test/rainspub.conf", ""},
		{"notExist/rainspub.conf", "open notExist/rainspub.conf: no such file or directory"},
		{"test/malformed.conf", "unexpected end of JSON input"},
	}
	for i, test := range tests {
		err := loadConfig(test.input)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: loadconfig() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && !reflect.DeepEqual(config, expectedConfig) {
			t.Errorf("%d: Loaded content is not as expected. expected=%v, actual=%v", i, expectedConfig, config)
		}
	}
}

func getAssertionWithTwoIPObjects() *rainslib.AssertionSection {
	return &rainslib.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			rainslib.Object{Type: rainslib.OTIP4Addr, Value: "129.132.128.139"}}}
}
*/
