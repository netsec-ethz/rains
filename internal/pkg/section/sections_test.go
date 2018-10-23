package section

/*func TestAssertionCopy(t *testing.T) {
	assertion := GetMessage().Content[0].(*Assertion)
	aCopy := assertion.Copy(assertion.Context, assertion.SubjectZone)
	CheckAssertion(assertion, aCopy, t)
	if assertion == aCopy {
		t.Error("Assertion was not copied. Pointer is still the same.")
	}
}

func TestShardCopy(t *testing.T) {
	shard := GetMessage().Content[1].(*Shard)
	sCopy := shard.Copy(shard.Context, shard.SubjectZone)
	CheckShard(shard, sCopy, t)
	if shard == sCopy {
		t.Error("Assertion was not copied. Pointer is still the same.")
	}
}

func TestAssertionInterval(t *testing.T) {
	var tests = []struct {
		input *Assertion
		want  string
	}{
		{&Assertion{SubjectName: "test"}, "test"},
		{new(Assertion), ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.want || test.input.End() != test.want {
			t.Errorf("%d: Assertion Begin and End are not as expected=%s actualBegin=%s actualEnd=%s", i, test.want, test.input.Begin(), test.input.End())
		}
	}
}

func TestShardInterval(t *testing.T) {
	var tests = []struct {
		input     *Shard
		wantBegin string
		wantEnd   string
	}{
		{&Shard{RangeFrom: "a", RangeTo: "z"}, "a", "z"},
		{new(Shard), "", ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.wantBegin || test.input.End() != test.wantEnd {
			t.Errorf("%d: Assertion Begin and End are not as expectedBegin=%s expectedEnd=%s actualBegin=%s actualEnd=%s", i,
				test.wantBegin, test.wantEnd, test.input.Begin(), test.input.End())
		}
	}
}

func TestZoneInterval(t *testing.T) {
	var tests = []struct {
		input *Zone
		want  string
	}{
		{new(Zone), ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.want || test.input.End() != test.want {
			t.Errorf("%d: Assertion Begin and End are not as expected=%s actualBegin=%s actualEnd=%s", i, test.want, test.input.Begin(), test.input.End())
		}
	}
}

func TestAssertionHash(t *testing.T) {
	var tests = []struct {
		input *Assertion
		want  string
	}{
		{nil, "A_nil"},
		{new(Assertion), "A____[]_[]"},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx", Content: GetAllValidObjects()[:3],
			Signatures: []Signature{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519}, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"A_name_zone_ctx_[OT:1 OV:{example.com [3 2]} OT:2 OV:2001:db8:: OT:3 OV:192.0.2.0]_[{KS=0 AT=1 VS=1000 VU=2000 KP=0 data=53696744617461}]"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong assertion hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestShardHash(t *testing.T) {
	var tests = []struct {
		input *Shard
		want  string
	}{
		{nil, "S_nil"},
		{new(Shard), "S_____[]_[]"},
		{&Shard{SubjectZone: "zone", Context: "ctx", RangeFrom: "RB", RangeTo: "RT", Content: []*Assertion{new(Assertion)},
			Signatures: []Signature{Signature{
				PublicKeyID: PublicKeyID{
					KeySpace:  RainsKeySpace,
					Algorithm: Ed25519,
					KeyPhase:  1,
				},
				ValidSince: 1000,
				ValidUntil: 2000,
				Data:       []byte("SigData")}}},
			"S_zone_ctx_RB_RT_[A____[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong shard hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestZoneHash(t *testing.T) {
	var tests = []struct {
		input *Zone
		want  string
	}{
		{nil, "Z_nil"},
		{new(Zone), "Z___[]_[]"},
		{&Zone{SubjectZone: "zone", Context: "ctx", Content: []WithSigForward{new(Assertion), new(Shard)},
			Signatures: []Signature{Signature{
				PublicKeyID: PublicKeyID{
					KeySpace:  RainsKeySpace,
					Algorithm: Ed25519,
					KeyPhase:  1,
				},
				ValidSince: 1000,
				ValidUntil: 2000,
				Data:       []byte("SigData")}}},
			"Z_zone_ctx_[A____[]_[] S_____[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]"},
		{&Zone{Content: []WithSigForward{new(Zone)}}, ""},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong zone hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestAddressAssertionHash(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR(ip4TestAddrCIDR32)
	_, subjectAddress2, _ := net.ParseCIDR(ip6TestAddrCIDR)
	objects1 := append(GetAllValidObjects()[3:5], GetAllValidObjects()[9])
	objects2 := []Object{GetAllValidObjects()[0]}
	var tests = []struct {
		input *AddrAssertion
		want  string
	}{
		{nil, "AA_nil"},
		{new(AddrAssertion), "AA_<nil>__[]_[]"},
		{
			&AddrAssertion{
				SubjectAddr: subjectAddress1,
				Context:     "ctx",
				Content:     objects2,
				Signatures: []Signature{
					Signature{
						PublicKeyID: PublicKeyID{
							KeySpace:  RainsKeySpace,
							Algorithm: Ed25519,
							KeyPhase:  1,
						},
						ValidSince: 1000,
						ValidUntil: 2000,
						Data:       []byte("SigData"),
					},
				},
			},
			"AA_192.0.2.0/32_ctx_[OT:1 OV:{example.com [3 2]}]_[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]",
		},
		{
			&AddrAssertion{
				SubjectAddr: subjectAddress2,
				Context:     "ctx",
				Content:     objects1,
				Signatures: []Signature{
					Signature{
						PublicKeyID: PublicKeyID{
							KeySpace:  RainsKeySpace,
							Algorithm: Ed25519,
							KeyPhase:  1,
						},
						ValidSince: 1000,
						ValidUntil: 2000,
						Data:       []byte("SigData"),
					},
				},
			},
			fmt.Sprintf("AA_2001:db8::/32_ctx_[OT:4 OV:example.com OT:5 OV:%s OT:10 OV:Registrant information]_[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]",
				objects1[1].Value.(PublicKey).String())},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong addressAssertion hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestAddressZoneHash(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR(ip4TestAddrCIDR32)
	_, subjectAddress2, _ := net.ParseCIDR(ip6TestAddrCIDR)
	var tests = []struct {
		input *AddressZoneSection
		want  string
	}{
		{nil, "AZ_nil"},
		{new(AddressZoneSection), "AZ_<nil>__[]_[]"},
		{
			&AddressZoneSection{
				SubjectAddr: subjectAddress1,
				Context:     "ctx",
				Content: []*AddrAssertion{
					new(AddrAssertion),
					new(AddrAssertion),
				},
				Signatures: []Signature{
					Signature{
						PublicKeyID: PublicKeyID{
							KeySpace:  RainsKeySpace,
							Algorithm: Ed25519,
							KeyPhase:  1,
						},
						ValidSince: 1000,
						ValidUntil: 2000,
						Data:       []byte("SigData"),
					},
				},
			},
			"AZ_192.0.2.0/32_ctx_[AA_<nil>__[]_[] AA_<nil>__[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]",
		},
		{
			&AddressZoneSection{
				SubjectAddr: subjectAddress2,
				Context:     "ctx",
				Content: []*AddrAssertion{
					new(AddrAssertion),
					new(AddrAssertion),
				},
				Signatures: []Signature{
					Signature{
						PublicKeyID: PublicKeyID{
							KeySpace:  RainsKeySpace,
							Algorithm: Ed25519,
							KeyPhase:  1,
						},
						ValidSince: 1000,
						ValidUntil: 2000,
						Data:       []byte("SigData"),
					},
				},
			},
			"AZ_2001:db8::/32_ctx_[AA_<nil>__[]_[] AA_<nil>__[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]",
		},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong addressZone hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestEqualContextZoneName(t *testing.T) {
	var tests = []struct {
		input *Assertion
		param *Assertion
		want  bool
	}{
		{new(Assertion), nil, false},
		{new(Assertion), new(Assertion), true},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"}, new(Assertion), false},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"}, true},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "diffname", SubjectZone: "zone", Context: "ctx"}, false},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "name", SubjectZone: "diffzone", Context: "ctx"}, false},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "diffctx"}, false},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "diffname", SubjectZone: "diffzone", Context: "diffctx"}, false},
	}
	for i, test := range tests {
		if test.input.EqualContextZoneName(test.param) != test.want {
			t.Errorf("%d: EqualContextZoneName() returns incorrect result. expected=%v, actual=%v", i, test.want, test.input.EqualContextZoneName(test.param))
		}
	}
}

func TestAssertionString(t *testing.T) {
	var tests = []struct {
		input *Assertion
		want  string
	}{
		{nil, "Assertion:nil"},
		{new(Assertion), "Assertion:[SN= SZ= CTX= CONTENT=[] SIG=[]]"},
		{
			&Assertion{
				SubjectName: "name",
				SubjectZone: "zone",
				Context:     "ctx",
				Content:     GetAllValidObjects()[:3],
				Signatures: []Signature{
					Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519, KeyPhase: 1}, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")},
					Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519, KeyPhase: 1}, ValidSince: 3000, ValidUntil: 4000, Data: []byte("SigData2")},
				},
			},
			"Assertion:[SN=name SZ=zone CTX=ctx CONTENT=[OT:1 OV:{example.com [3 2]} OT:2 OV:2001:db8:: OT:3 OV:192.0.2.0] SIG=[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461} {KS=0 AT=1 VS=3000 VU=4000 KP=1 data=5369674461746132}]]",
		},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong assertion String(). expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestShardString(t *testing.T) {
	var tests = []struct {
		input *Shard
		want  string
	}{
		{nil, "Shard:nil"},
		{new(Shard), "Shard:[SZ= CTX= RF= RT= CONTENT=[] SIG=[]]"},
		{
			&Shard{
				SubjectZone: "zone",
				Context:     "ctx",
				RangeFrom:   "RF",
				RangeTo:     "RT",
				Content: []*Assertion{
					new(Assertion),
				},
				Signatures: []Signature{
					Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519, KeyPhase: 1}, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"Shard:[SZ=zone CTX=ctx RF=RF RT=RT CONTENT=[Assertion:[SN= SZ= CTX= CONTENT=[] SIG=[]]] SIG=[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]]"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong shard String. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestZoneString(t *testing.T) {
	var tests = []struct {
		input *Zone
		want  string
	}{
		{nil, "Zone:nil"},
		{new(Zone), "Zone:[SZ= CTX= CONTENT=[] SIG=[]]"},
		{
			&Zone{
				SubjectZone: "zone",
				Context:     "ctx",
				Content: []WithSigForward{
					new(Assertion),
					new(Shard),
				},
				Signatures: []Signature{
					Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519, KeyPhase: 1}, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"Zone:[SZ=zone CTX=ctx CONTENT=[Assertion:[SN= SZ= CTX= CONTENT=[] SIG=[]] Shard:[SZ= CTX= RF= RT= CONTENT=[] SIG=[]]] SIG=[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]]"},
		{&Zone{Content: []WithSigForward{new(Zone)}}, "Zone:[SZ= CTX= CONTENT=[Zone:[SZ= CTX= CONTENT=[] SIG=[]]] SIG=[]]"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong zone String. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestAddressAssertionString(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR(ip4TestAddrCIDR32)
	_, subjectAddress2, _ := net.ParseCIDR(ip6TestAddrCIDR)
	objects1 := append(GetAllValidObjects()[3:5], GetAllValidObjects()[9])
	objects2 := []Object{GetAllValidObjects()[0]}
	var tests = []struct {
		input *AddrAssertion
		want  string
	}{
		{nil, "AddressAssertion:nil"},
		{new(AddrAssertion), "AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]]"},
		{
			&AddrAssertion{
				SubjectAddr: subjectAddress1,
				Context:     "ctx",
				Content:     objects2,
				Signatures: []Signature{
					Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519, KeyPhase: 1}, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"AddressAssertion:[SA=192.0.2.0/32 CTX=ctx CONTENT=[OT:1 OV:{example.com [3 2]}] SIG=[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]]",
		},
		{
			&AddrAssertion{
				SubjectAddr: subjectAddress2,
				Context:     "ctx",
				Content:     objects1,
				Signatures: []Signature{
					Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519, KeyPhase: 1}, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")},
				},
			},
			fmt.Sprintf("AddressAssertion:[SA=2001:db8::/32 CTX=ctx CONTENT=[OT:4 OV:example.com OT:5 OV:%s OT:10 OV:Registrant information] SIG=[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]]",
				objects1[1].Value.(PublicKey).String()),
		},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong addressAssertion String. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestAddressZoneString(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR(ip4TestAddrCIDR32)
	_, subjectAddress2, _ := net.ParseCIDR(ip6TestAddrCIDR)
	var tests = []struct {
		input *AddressZoneSection
		want  string
	}{
		{nil, "AddressZone:nil"},
		{new(AddressZoneSection), "AddressZone:[SA=<nil> CTX= CONTENT=[] SIG=[]]"},
		{&AddressZoneSection{
			SubjectAddr: subjectAddress1,
			Context:     "ctx",
			Content: []*AddrAssertion{
				new(AddrAssertion),
				new(AddrAssertion),
			},
			Signatures: []Signature{Signature{
				PublicKeyID: PublicKeyID{
					KeySpace:  RainsKeySpace,
					Algorithm: Ed25519,
					KeyPhase:  1,
				},
				ValidSince: 1000,
				ValidUntil: 2000,
				Data:       []byte("SigData"),
			}},
		},
			"AddressZone:[SA=192.0.2.0/32 CTX=ctx CONTENT=[AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]] AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]]] SIG=[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]]"},
		{
			&AddressZoneSection{
				SubjectAddr: subjectAddress2,
				Context:     "ctx",
				Content: []*AddrAssertion{
					new(AddrAssertion),
					new(AddrAssertion),
				},
				Signatures: []Signature{
					Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519, KeyPhase: 1}, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"AddressZone:[SA=2001:db8::/32 CTX=ctx CONTENT=[AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]] AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]]] SIG=[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]]"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong addressZone String. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestQueryString(t *testing.T) {
	var tests = []struct {
		input *QueryForward
		want  string
	}{
		{nil, "Query:nil"},
		{
			new(QueryForward),
			"Query:[CTX= NA= TYPE=[] EXP=0 OPT=[]]",
		},
		{
			&QueryForward{
				Context:    "ctx",
				Name:       "name",
				Types:      []ObjectType{OTName},
				Expiration: 100,
				Options:    []QueryOption{QOMinE2ELatency, QOMinInfoLeakage},
			},
			"Query:[CTX=ctx NA=name TYPE=[1] EXP=100 OPT=[1 3]]",
		},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong query String(). expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestAddressQueryString(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR(ip4TestAddrCIDR32)
	_, subjectAddress2, _ := net.ParseCIDR(ip6TestAddrCIDR)
	var tests = []struct {
		input *AddrQuery
		want  string
	}{
		{nil, "AddressQuery:nil"},
		{
			new(AddrQuery),
			"AddressQuery:[SA=<nil> CTX= TYPE=[] EXP=0 OPT=[]]",
		},
		{
			&AddrQuery{
				SubjectAddr: subjectAddress1,
				Context:     "ctx",
				Types:       []ObjectType{OTName},
				Expiration:  100,
				Options:     []QueryOption{QOMinE2ELatency, QOMinInfoLeakage},
			},
			"AddressQuery:[SA=192.0.2.0/32 CTX=ctx TYPE=[1] EXP=100 OPT=[1 3]]",
		},
		{
			&AddrQuery{
				SubjectAddr: subjectAddress2,
				Context:     "ctx",
				Types:       []ObjectType{OTName},
				Expiration:  100,
				Options:     []QueryOption{QOMinE2ELatency, QOMinInfoLeakage},
			},
			"AddressQuery:[SA=2001:db8::/32 CTX=ctx TYPE=[1] EXP=100 OPT=[1 3]]",
		},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong addressQuery String(). expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestNotificationString(t *testing.T) {
	token := GenerateToken()
	var tests = []struct {
		input *Notification
		want  string
	}{
		{nil, "Notification:nil"},
		{new(Notification), "Notification:[TOK=00000000000000000000000000000000 TYPE=0 DATA=]"},
		{&Notification{Token: token, Type: NTBadMessage, Data: "notificationData"},
			fmt.Sprintf("Notification:[TOK=%s TYPE=400 DATA=notificationData]", hex.EncodeToString(token[:]))},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong notification String(). expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestContainsOptions(t *testing.T) {
	var tests = []struct {
		input []QueryOption
		param QueryOption
		want  bool
	}{
		{[]QueryOption{QOCachedAnswersOnly, QOExpiredAssertionsOk}, QOCachedAnswersOnly, true},
		{[]QueryOption{QOCachedAnswersOnly, QOExpiredAssertionsOk}, QOExpiredAssertionsOk, true},
		{[]QueryOption{}, QOCachedAnswersOnly, false},
		{[]QueryOption{QOExpiredAssertionsOk}, QOCachedAnswersOnly, false},
	}
	for i, test := range tests {
		if containsOption(test.param, test.input) != test.want {
			t.Errorf("%d: containsOptions response incorrect. expected=%v, actual=%v", i, test.want, containsOption(test.param, test.input))
		}
		query := &QueryForward{Options: test.input}
		addressquery := &AddrQuery{Options: test.input}
		if query.ContainsOption(test.param) != test.want {
			t.Errorf("%d: query.ContainsOptions response incorrect. expected=%v, actual=%v", i, test.want, containsOption(test.param, test.input))
		}
		if addressquery.ContainsOption(test.param) != test.want {
			t.Errorf("%d: addressQuery.ContainsOptions response incorrect. expected=%v, actual=%v", i, test.want, containsOption(test.param, test.input))
		}
	}
}

func TestNotificationCompareTo(t *testing.T) {
	ns := sortedNotifications(9)
	var shuffled []Section
	for _, n := range ns {
		shuffled = append(shuffled, n)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*Notification).CompareTo(shuffled[j].(*Notification)) < 0
	})
	for i, n := range ns {
		CheckNotification(n, shuffled[i].(*Notification), t)
	}
}

func TestAssertionCompareTo(t *testing.T) {
	assertions := sortedAssertions(10)
	var shuffled []Section
	for _, a := range assertions {
		shuffled = append(shuffled, a)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*Assertion).CompareTo(shuffled[j].(*Assertion)) < 0
	})
	for i, a := range assertions {
		CheckAssertion(a, shuffled[i].(*Assertion), t)
	}
	a1 := &Assertion{}
	a2 := &Assertion{Content: []Object{Object{}}}
	if a1.CompareTo(a2) != -1 {
		t.Error("Different content length are not sorted correctly")
	}
	if a2.CompareTo(a1) != 1 {
		t.Error("Different content length are not sorted correctly")
	}
}

func TestShardCompareTo(t *testing.T) {
	shards := sortedShards(5)
	var shuffled []Section
	for _, s := range shards {
		shuffled = append(shuffled, s)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*Shard).CompareTo(shuffled[j].(*Shard)) < 0
	})
	for i, s := range shards {
		CheckShard(s, shuffled[i].(*Shard), t)
	}
	s1 := &Shard{}
	s2 := &Shard{Content: []*Assertion{&Assertion{}}}
	if s1.CompareTo(s2) != -1 {
		t.Error("Different content length are not sorted correctly")
	}
	if s2.CompareTo(s1) != 1 {
		t.Error("Different content length are not sorted correctly")
	}
}

func TestZoneCompareTo(t *testing.T) {
	zones := sortedZones(3)
	var shuffled []Section
	for _, z := range zones {
		shuffled = append(shuffled, z)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*Zone).CompareTo(shuffled[j].(*Zone)) < 0
	})
	for i, z := range zones {
		CheckZone(z, shuffled[i].(*Zone), t)
	}
	z1 := &Zone{}
	z2 := &Zone{Content: []WithSigForward{&Assertion{}}}
	if z1.CompareTo(z2) != -1 {
		t.Error("Different content length are not sorted correctly")
	}
	if z2.CompareTo(z1) != 1 {
		t.Error("Different content length are not sorted correctly")
	}
	z1 = &Zone{Content: []WithSigForward{&Assertion{}}}
	z2 = &Zone{Content: []WithSigForward{&Zone{}}} //invalid type within Content
	if z2.CompareTo(z1) != 0 {
		t.Error("Different content length are not sorted correctly")
	}
}
func TestQueryCompareTo(t *testing.T) {
	queries := sortedQueries(5)
	var shuffled []Section
	for _, q := range queries {
		shuffled = append(shuffled, q)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*QueryForward).CompareTo(shuffled[j].(*QueryForward)) < 0
	})
	for i, q := range queries {
		CheckQuery(q, shuffled[i].(*QueryForward), t)
	}
}

func TestAddressAssertionCompareTo(t *testing.T) {
	assertions := sortedAddressAssertions(9)
	var shuffled []Section
	for _, a := range assertions {
		shuffled = append(shuffled, a)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*AddrAssertion).CompareTo(shuffled[j].(*AddrAssertion)) < 0
	})
	for i, a := range assertions {
		CheckAddressAssertion(a, shuffled[i].(*AddrAssertion), t)
	}
	_, subjectAddress, _ := net.ParseCIDR(ip4TestAddrCIDR24)
	a1 := &AddrAssertion{SubjectAddr: subjectAddress}
	a2 := &AddrAssertion{SubjectAddr: subjectAddress, Content: []Object{Object{}}}
	if a1.CompareTo(a2) != -1 {
		t.Error("Different content length are not sorted correctly")
	}
	if a2.CompareTo(a1) != 1 {
		t.Error("Different content length are not sorted correctly")
	}
}

func TestAddressZoneCompareTo(t *testing.T) {
	zones := sortedAddressZones(4)
	var shuffled []Section
	for _, z := range zones {
		shuffled = append(shuffled, z)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*AddressZoneSection).CompareTo(shuffled[j].(*AddressZoneSection)) < 0
	})
	for i, z := range zones {
		CheckAddressZone(z, shuffled[i].(*AddressZoneSection), t)
	}
	_, subjectAddress, _ := net.ParseCIDR(ip4TestAddrCIDR24)
	z1 := &AddressZoneSection{SubjectAddr: subjectAddress}
	z2 := &AddressZoneSection{SubjectAddr: subjectAddress, Content: []*AddrAssertion{&AddrAssertion{}}}
	if z1.CompareTo(z2) != -1 {
		t.Error("Different content length are not sorted correctly")
	}
	if z2.CompareTo(z1) != 1 {
		t.Error("Different content length are not sorted correctly")
	}
}

func TestAddressQueryCompareTo(t *testing.T) {
	queries := sortedAddressQueries(2)
	var shuffled []Section
	for _, q := range queries {
		shuffled = append(shuffled, q)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*AddrQuery).CompareTo(shuffled[j].(*AddrQuery)) < 0
	})
	for i, q := range queries {
		CheckAddressQuery(q, shuffled[i].(*AddrQuery), t)
	}
}

func shuffleSections(sections []Section) {
	for i := len(sections) - 1; i > 0; i-- {
		j := rand.Intn(i)
		sections[i], sections[j] = sections[j], sections[i]
	}
}

func TestAssertionSort(t *testing.T) {
	var tests = []struct {
		input  []Object
		sorted []Object
	}{
		{
			[]Object{Object{Type: OTIP4Addr, Value: "192.0.2.0"}, Object{Type: OTName, Value: NameObject{Name: "name", Types: []ObjectType{OTDelegation, OTName}}}},
			[]Object{Object{Type: OTName, Value: NameObject{Name: "name", Types: []ObjectType{OTName, OTDelegation}}}, Object{Type: OTIP4Addr, Value: "192.0.2.0"}},
		},
	}
	for i, test := range tests {
		a := &Assertion{Content: test.input}
		a.Sort()
		if !reflect.DeepEqual(a.Content, test.sorted) {
			t.Errorf("%d: Assertion.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, a.Content)
		}
	}
}

func TestShardSort(t *testing.T) {
	var tests = []struct {
		input  []*Assertion
		sorted []*Assertion
	}{
		{
			[]*Assertion{
				&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}},
				&Assertion{Content: []Object{Object{Type: OTIP4Addr}, Object{Type: OTName}}},
			},
			[]*Assertion{
				&Assertion{Content: []Object{Object{Type: OTName}, Object{Type: OTIP4Addr}}},
				&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}},
			},
		},
	}
	for i, test := range tests {
		s := &Shard{Content: test.input}
		s.Sort()
		if !reflect.DeepEqual(s.Content, test.sorted) {
			t.Errorf("%d: Shard.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, s.Content)
		}
	}
}

func TestZoneSort(t *testing.T) {
	var tests = []struct {
		input  []WithSigForward
		sorted []WithSigForward
	}{
		{
			[]WithSigForward{
				&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}}, //Assertion compared with Assertion
				&Assertion{Content: []Object{Object{Type: OTIP4Addr}, Object{Type: OTName}}},
			},
			[]WithSigForward{
				&Assertion{Content: []Object{Object{Type: OTName}, Object{Type: OTIP4Addr}}},
				&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}},
			},
		},
		{
			[]WithSigForward{&Shard{}, &Assertion{}}, //Assertion compared with Shard
			[]WithSigForward{&Assertion{}, &Shard{}},
		},
		{
			[]WithSigForward{&Assertion{}, &Shard{}}, //Assertion compared with Shard
			[]WithSigForward{&Assertion{}, &Shard{}},
		},
		{
			[]WithSigForward{ //Shard compared with Shard
				&Shard{Content: []*Assertion{&Assertion{SubjectName: "b"}, &Assertion{SubjectName: "d"}}},
				&Shard{Content: []*Assertion{&Assertion{SubjectName: "c"}, &Assertion{SubjectName: "a"}}},
			},
			[]WithSigForward{
				&Shard{Content: []*Assertion{&Assertion{SubjectName: "a"}, &Assertion{SubjectName: "c"}}},
				&Shard{Content: []*Assertion{&Assertion{SubjectName: "b"}, &Assertion{SubjectName: "d"}}},
			},
		},
	}
	for i, test := range tests {
		z := &Zone{Content: test.input}
		z.Sort()
		if !reflect.DeepEqual(z.Content, test.sorted) {
			t.Errorf("%d: Zone.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, z.Content)
		}
	}
	//no panic when invalid content
	z := &Zone{Content: []WithSigForward{&Zone{}, &Zone{}}}
	z.Sort()
}

func TestQuerySort(t *testing.T) {
	var tests = []struct {
		input  []QueryOption
		sorted []QueryOption
	}{
		{[]QueryOption{QueryOption(5), QueryOption(3)}, []QueryOption{QueryOption(3), QueryOption(5)}},
	}
	for i, test := range tests {
		q := &QueryForward{Options: test.input}
		q.Sort()
		if !reflect.DeepEqual(q.Options, test.sorted) {
			t.Errorf("%d: Query.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, q.Options)
		}
	}
}

func TestAddressAssertionSort(t *testing.T) {
	var tests = []struct {
		input  []Object
		sorted []Object
	}{
		{[]Object{Object{Type: OTIP4Addr, Value: "192.0.2.0"}, Object{Type: OTName, Value: NameObject{Name: "name", Types: []ObjectType{OTDelegation, OTName}}}},
			[]Object{Object{Type: OTName, Value: NameObject{Name: "name", Types: []ObjectType{OTName, OTDelegation}}}, Object{Type: OTIP4Addr, Value: "192.0.2.0"}}},
	}
	for i, test := range tests {
		a := &AddrAssertion{Content: test.input}
		a.Sort()
		if !reflect.DeepEqual(a.Content, test.sorted) {
			t.Errorf("%d: AddressAssertion.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, a.Content)
		}
	}
}

func TestAddressZoneSort(t *testing.T) {
	_, subjectAddress, _ := net.ParseCIDR(ip4TestAddrCIDR24)
	var tests = []struct {
		input  []*AddrAssertion
		sorted []*AddrAssertion
	}{
		{
			[]*AddrAssertion{
				&AddrAssertion{SubjectAddr: subjectAddress, Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}},
				&AddrAssertion{SubjectAddr: subjectAddress, Content: []Object{Object{Type: OTIP4Addr}, Object{Type: OTName}}},
			},
			[]*AddrAssertion{
				&AddrAssertion{SubjectAddr: subjectAddress, Content: []Object{Object{Type: OTName}, Object{Type: OTIP4Addr}}},
				&AddrAssertion{SubjectAddr: subjectAddress, Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}},
			},
		},
	}
	for i, test := range tests {
		z := &AddressZoneSection{Content: test.input}
		z.Sort()
		if !reflect.DeepEqual(z.Content, test.sorted) {
			t.Errorf("%d: AddressZone.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, z.Content)
		}
	}
}

func TestAddressQuerySort(t *testing.T) {
	var tests = []struct {
		input  []QueryOption
		sorted []QueryOption
	}{
		{[]QueryOption{QueryOption(5), QueryOption(3)}, []QueryOption{QueryOption(3), QueryOption(5)}},
	}
	for i, test := range tests {
		q := &AddrQuery{Options: test.input}
		q.Sort()
		if !reflect.DeepEqual(q.Options, test.sorted) {
			t.Errorf("%d: Query.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, q.Options)
		}
	}
}

func TestSigs(t *testing.T) {
	var tests = []struct {
		input  []Signature
		param  KeySpaceID
		output []Signature
	}{
		{[]Signature{Signature{PublicKeyID: PublicKeyID{KeySpace: KeySpaceID(-1)}}, Signature{}}, RainsKeySpace, []Signature{Signature{}}},
	}
	for i, test := range tests {
		var s WithSig
		s = &Assertion{Signatures: test.input}
		sigs := s.Sigs(test.param)
		if !reflect.DeepEqual(sigs, test.output) {
			t.Errorf("%d: assertion.Sigs() does not return the expected signatures expected=%v actual=%v", i, test.output, sigs)
		}
		s = &Shard{Signatures: test.input}
		sigs = s.Sigs(test.param)
		if !reflect.DeepEqual(sigs, test.output) {
			t.Errorf("%d: shard.Sigs() does not return the expected signatures expected=%v actual=%v", i, test.output, sigs)
		}
		s = &Zone{Signatures: test.input}
		sigs = s.Sigs(test.param)
		if !reflect.DeepEqual(sigs, test.output) {
			t.Errorf("%d: zone.Sigs() does not return the expected signatures expected=%v actual=%v", i, test.output, sigs)
		}
		s = &AddrAssertion{Signatures: test.input}
		sigs = s.Sigs(test.param)
		if !reflect.DeepEqual(sigs, test.output) {
			t.Errorf("%d: addressAssertion.Sigs() does not return the expected signatures expected=%v actual=%v", i, test.output, sigs)
		}
		s = &AddressZoneSection{Signatures: test.input}
		sigs = s.Sigs(test.param)
		if !reflect.DeepEqual(sigs, test.output) {
			t.Errorf("%d: addressZone.Sigs() does not return the expected signatures expected=%v actual=%v", i, test.output, sigs)
		}
	}
}

func TestAssertionsByNameAndTypes(t *testing.T) {
	ss := Shard{
		Content: make([]*Assertion, 0),
	}
	as1 := &Assertion{
		SubjectName: "example",
		SubjectZone: "com.",
		Content: []Object{Object{
			Type:  OTIP4Addr,
			Value: "127.0.0.1",
		},
			Object{
				Type:  OTIP6Addr,
				Value: "::1",
			}},
	}
	as2 := &Assertion{
		SubjectName: "example",
		SubjectZone: "com.",
		Content: []Object{
			Object{
				Type:  OTRegistrant,
				Value: "John Doe",
			},
			Object{
				Type:  OTRegistrar,
				Value: "Jane Doe",
			},
		}}
	ss.Content = append(ss.Content, as1, as2)
	res1 := ss.AssertionsByNameAndTypes("example", []ObjectType{OTRegistrar, OTIP6Addr})
	expect1 := []*Assertion{as1, as2}
	if len(res1) != 2 {
		t.Errorf("expected 2 assertionsections, but got %v", len(res1))
	}
	if !reflect.DeepEqual(res1, expect1) {
		t.Errorf("mismatched returned assertionsections: got %v, want %v", res1, expect1)
	}
	res2 := ss.AssertionsByNameAndTypes("non.existant", []ObjectType{OTRegistrar, OTIP6Addr})
	if len(res2) != 0 {
		t.Errorf("expected 0 assertionsections but got %d: %v", len(res2), res2)
	}
	res3 := ss.AssertionsByNameAndTypes("example", []ObjectType{OTIP6Addr})
	expect3 := []*Assertion{as1}
	if len(res3) != 1 {
		t.Errorf("expected 1 assertinsections but got %d: %v", len(res3), res3)
	}
	if !reflect.DeepEqual(res3, expect3) {
		t.Errorf("mismatched returned assertionsections: got %v, want %v", res3, expect3)
	}
}

func TestInRange(t *testing.T) {
	ss := Shard{
		RangeFrom: "abc",
		RangeTo:   "xyz",
	}
	testMatrix := []struct {
		Input  string
		Output bool
	}{
		{
			Input:  "aaa",
			Output: false,
		},
		{
			Input:  "abc",
			Output: false,
		},
		{
			Input:  "abcdef",
			Output: true,
		},
		{
			Input:  "zzz",
			Output: false,
		},
	}
	for i, testCase := range testMatrix {
		if out := ss.InRange(testCase.Input); out != testCase.Output {
			t.Errorf("case %d: expected response of %t from InRange, but got %t with input %s",
				i, out, testCase.Output, testCase.Input)
		}
	}
}

func TestIsConsistent(t *testing.T) {
	testMatrix := []struct {
		section    *Shard
		wellformed bool
	}{
		{
			section:    &Shard{SubjectZone: "legitimate.zone"},
			wellformed: true,
		},
		{
			section: &Shard{
				SubjectZone: "legitimate.zone",
				RangeFrom:   "abc",
				RangeTo:     "xyz",
				Content: []*Assertion{
					&Assertion{
						SubjectName: "aaa",
					},
				},
			},
			wellformed: false,
		},
		{
			section: &Shard{
				SubjectZone: "legitimate.zone",
				RangeFrom:   "abc",
				RangeTo:     "xyz",
				Content: []*Assertion{
					&Assertion{
						SubjectName: "def",
					},
				},
			},
			wellformed: true,
		},
		{
			section: &Shard{
				SubjectZone: "legitimate.zone",
				RangeFrom:   "abc",
				RangeTo:     "xyz",
			},
			wellformed: true,
		},
	}
	for i, testCase := range testMatrix {
		if res := testCase.section.IsConsistent(); res != testCase.wellformed {
			t.Errorf("case %d: wrong consistency: got %t, want %t", i, res, testCase.wellformed)
		}
	}
}

func TestSectionsByNamesAndTypes(t *testing.T) {
	zs := &Zone{
		Content: []WithSigForward{
			&Assertion{
				SubjectName: "domain",
				SubjectZone: "com.",
				Content: []Object{
					Object{
						Type:  OTRegistrant,
						Value: "Jane Doe",
					},
				},
			},
			&Assertion{
				SubjectName: "example",
				SubjectZone: "ch.",
				Content: []Object{
					Object{
						Type:  OTIP4Addr,
						Value: "127.0.0.1",
					},
				},
			},
			&Shard{
				RangeFrom: "as",
				RangeTo:   "b",
				Content: []*Assertion{
					&Assertion{
						SubjectName: "as559.net",
						Content: []Object{
							Object{
								Type:  OTIP6Addr,
								Value: "2001:67c:10ec::cafe",
							},
						},
					},
				},
			},
		},
	}
	testMatrix := []struct {
		subjectName string
		types       []ObjectType
		as          []*Assertion
		ss          []*Shard
	}{
		{
			subjectName: "example",
			types:       []ObjectType{OTIP4Addr},
			as:          []*Assertion{zs.Content[1].(*Assertion)},
		},
		{
			subjectName: "domain",
			types:       []ObjectType{OTRegistrant},
			as:          []*Assertion{zs.Content[0].(*Assertion)},
		},
		{
			subjectName: "as559.net",
			types:       []ObjectType{OTIP6Addr},
			as:          []*Assertion{zs.Content[2].(*Shard).Content[0]},
			ss:          []*Shard{zs.Content[2].(*Shard)},
		},
	}
	for i, testCase := range testMatrix {
		as, ss := zs.SectionsByNameAndTypes(testCase.subjectName, testCase.types)
		if !reflect.DeepEqual(as, testCase.as) {
			t.Errorf("case %d: mismatched assertionSections: got %v, want %v", i, as, testCase.as)
		}
		if !reflect.DeepEqual(ss, testCase.ss) {
			t.Errorf("case %d: mismatched shardSections: got %v, want %v", i, ss, testCase.ss)
		}
	}
}*/
