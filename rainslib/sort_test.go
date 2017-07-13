package rainslib

import (
	"net"
	"strconv"

	"fmt"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

func sortedNameObjects(nof int) []NameObject {
	objects := []NameObject{}
	for i := 0; i < nof; i++ {
		objTypes := nof
		if objTypes > 13 {
			objTypes = 13
		}
		for j := 0; j < objTypes; j++ {
			objects = append(objects, NameObject{Name: strconv.Itoa(i), Types: []ObjectType{ObjectType(j)}})
		}
		for j := 0; j < objTypes-1; j++ { //-1 to make sure that there are always 2 elements in the slice
			for k := j + 1; k < objTypes; k++ {
				objects = append(objects, NameObject{Name: strconv.Itoa(i), Types: []ObjectType{ObjectType(j), ObjectType(k)}})
			}
		}
	}
	objects = append(objects, objects[len(objects)-1])
	return objects
}

func sortedPublicKeys(nof int) []PublicKey {
	if nof > 255 {
		log.Error("nof must be smaller than 256", "nof", nof)
		nof = 255
	}
	pkeys := []PublicKey{}
	for i := 1; i < 5; i++ {
		for j := 0; j < 1; j++ {
			for k := 0; k < nof; k++ {
				for l := 0; l < nof; l++ {
					for m := 0; m < nof; m++ {
						pkeys = append(pkeys, PublicKey{
							Type:       SignatureAlgorithmType(i),
							KeySpace:   KeySpaceID(j),
							ValidSince: int64(k),
							ValidUntil: int64(l),
							Key:        ed25519.PublicKey([]byte{byte(m)}),
						})
					}
				}
			}
		}
	}
	pkeys = append(pkeys, pkeys[len(pkeys)-1])
	return pkeys
}

func sortedCertificates(nof int) []CertificateObject {
	if nof > 255 {
		log.Error("nof must be smaller than 256", "nof", nof)
		nof = 255
	}
	certs := []CertificateObject{}
	for i := 0; i < 2; i++ {
		for j := 2; j < 4; j++ {
			for k := 0; k < 4; k++ {
				for l := 0; l < nof; l++ {
					certs = append(certs, CertificateObject{
						Type:     ProtocolType(i),
						Usage:    CertificateUsage(j),
						HashAlgo: HashAlgorithmType(k),
						Data:     []byte{byte(l)},
					})
				}
			}
		}
	}
	certs = append(certs, certs[len(certs)-1])
	return certs
}

func sortedServiceInfo(nof int) []ServiceInfo {
	sis := []ServiceInfo{}
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for k := 0; k < nof; k++ {
				sis = append(sis, ServiceInfo{
					Name:     strconv.Itoa(i),
					Port:     uint16(j),
					Priority: uint(k),
				})
			}
		}
	}
	sis = append(sis, sis[len(sis)-1])
	return sis
}

func sortedObjects(nofObj int) []Object {
	objects := []Object{}
	if nofObj > 13 {
		nofObj = 13
	}
	nos := sortedNameObjects(nofObj)
	pkeys := sortedPublicKeys(nofObj)
	certs := sortedCertificates(nofObj)
	sis := sortedServiceInfo(nofObj)
	for i := 0; i < nofObj; i++ {
		for j := 0; j < nofObj/2; j++ {
			var value interface{}
			switch i {
			case 0:
				value = nos[j]
			case 1:
				value = strconv.Itoa(j) //ip6
			case 2:
				value = strconv.Itoa(j) //ip4
			case 3:
				value = strconv.Itoa(j) //redir
			case 4:
				value = pkeys[j]
			case 5:
				value = NamesetExpression(strconv.Itoa(j))
			case 6:
				value = certs[j]
			case 7:
				value = sis[j]
			case 8:
				value = strconv.Itoa(j) //registrar
			case 9:
				value = strconv.Itoa(j) //registrant
			case 10:
				value = pkeys[j]
			case 11:
				value = pkeys[j]
			case 12:
				value = pkeys[j]

			}
			objects = append(objects, Object{
				Type:  ObjectType(i + 1),
				Value: value,
			})
		}
	}
	return objects
}

func sortedAssertions(nof int) []*AssertionSection {
	assertions := []*AssertionSection{}
	objs := sortedObjects(13)
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for k := 0; k < nof; k++ {
				//TODO CFE extend this test when we support multiple types per assertion
				for l := 0; l < 78; l++ {
					assertions = append(assertions, &AssertionSection{
						SubjectName: strconv.Itoa(i),
						SubjectZone: strconv.Itoa(j),
						Context:     strconv.Itoa(k),
						Content:     []Object{objs[l]},
					})
				}
			}
		}
	}
	assertions = append(assertions, assertions[len(assertions)-1]) //equals
	return assertions
}

func sortedShards(nof int) []*ShardSection {
	shards := []*ShardSection{}
	assertions := sortedAssertions(2)
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for k := 0; k < nof; k++ {
				for l := 0; l < nof; l++ {
					//TODO CFE extend this test when we support multiple types per assertion
					for m := 0; m < 312; m++ {
						shards = append(shards, &ShardSection{
							SubjectZone: strconv.Itoa(i),
							Context:     strconv.Itoa(j),
							RangeFrom:   strconv.Itoa(k),
							RangeTo:     strconv.Itoa(l),
							Content:     []*AssertionSection{assertions[m]},
						})
					}
				}
			}
		}
	}
	shards = append(shards, shards[len(shards)-1]) //equals
	return shards
}

func sortedZones(nof int) []*ZoneSection {
	zones := []*ZoneSection{}
	assertions := sortedAssertions(5)
	shards := sortedShards(2)
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			//TODO CFE extend this test when we support multiple types per assertion
			for l := 0; l < 9751; l++ {
				zones = append(zones, &ZoneSection{
					SubjectZone: strconv.Itoa(i),
					Context:     strconv.Itoa(j),
					Content:     []MessageSectionWithSigForward{assertions[l]},
				})
			}
			for l := 0; l < 4993; l++ {
				zones = append(zones, &ZoneSection{
					SubjectZone: strconv.Itoa(i),
					Context:     strconv.Itoa(j),
					Content:     []MessageSectionWithSigForward{shards[l]},
				})
			}
		}
	}
	zones = append(zones, zones[len(zones)-1]) //equals
	return zones
}

func sortedQueries(nof int) []*QuerySection {
	queries := []*QuerySection{}
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for k := 0; k < 13; k++ {
				for l := 0; l < nof; l++ {
					for m := 0; m < 8; m++ {
						//TODO CFE extend this test when we support multiple types per assertion
						queries = append(queries, &QuerySection{
							Context: strconv.Itoa(i),
							Name:    strconv.Itoa(j),
							Types:   []ObjectType{ObjectType(k)},
							Expires: int64(l),
							Options: []QueryOption{QueryOption(m)},
						})
					}
					for m := 0; m < 7; m++ {
						for n := m + 1; n < 8; n++ {
							//TODO CFE extend this test when we support multiple types per assertion
							queries = append(queries, &QuerySection{
								Context: strconv.Itoa(i),
								Name:    strconv.Itoa(j),
								Types:   []ObjectType{ObjectType(k)},
								Expires: int64(l),
								Options: []QueryOption{QueryOption(m), QueryOption(n)},
							})
						}
					}
				}

			}
		}
	}
	queries = append(queries, queries[len(queries)-1])
	return queries
}

func sortedAddressAssertions(nof int) []*AddressAssertionSection {
	if nof > 9 {
		log.Error("nof must be smaller than 10", "nof", nof)
		//otherwise subjectAddr first value is now 2 digit and in string comparison "10." sorts before "2.",
		//which makes the test much more complicated
		nof = 9
	}
	assertions := []*AddressAssertionSection{}
	objs := sortedObjects(13)
	for i := 1; i < nof+1; i++ {
		//We start from 1 as leading zero's are omitted in IPv6 format while there are present in ipv4.
		//Thus leading zero is a special case. Where IPv6 are sorted before IPv4.
		_, subjectAddress, _ := net.ParseCIDR(fmt.Sprintf("%d.0.0.1/32", i))
		_, subjectAddress2, _ := net.ParseCIDR(fmt.Sprintf("%d::/64", i))
		for j := 0; j < nof; j++ {
			//TODO CFE extend this test when we support multiple types per assertion
			for l := 0; l < 78; l++ {
				assertions = append(assertions, &AddressAssertionSection{
					SubjectAddr: subjectAddress,
					Context:     strconv.Itoa(j),
					Content:     []Object{objs[l]},
				})
			}
		}
		for j := 0; j < nof; j++ {
			//TODO CFE extend this test when we support multiple types per assertion
			for l := 0; l < 78; l++ {
				assertions = append(assertions, &AddressAssertionSection{
					SubjectAddr: subjectAddress2,
					Context:     strconv.Itoa(j),
					Content:     []Object{objs[l]},
				})

			}
		}
	}
	assertions = append(assertions, assertions[len(assertions)-1]) //equals
	return assertions
}

func sortedAddressZones(nof int) []*AddressZoneSection {
	if nof > 9 {
		log.Error("nof must be smaller than 10", "nof", nof)
		//otherwise subjectAddr first value is now 2 digit and in string comparison "10." sorts before "2.",
		//which makes the test much more complicated
		nof = 9
	}
	zones := []*AddressZoneSection{}
	assertions := sortedAddressAssertions(3)
	for i := 1; i < nof+1; i++ {
		//We start from 1 as leading zero's are omitted in IPv6 format while there are present in ipv4.
		//Thus leading zero is a special case. Where IPv6 are sorted before IPv4.
		_, subjectAddress, _ := net.ParseCIDR(fmt.Sprintf("%d.0.0.1/32", i))
		_, subjectAddress2, _ := net.ParseCIDR(fmt.Sprintf("%d::/64", i))
		for j := 0; j < nof; j++ {
			//TODO CFE extend this test when we support multiple types per assertion
			for l := 0; l < 1405; l++ {
				zones = append(zones, &AddressZoneSection{
					SubjectAddr: subjectAddress,
					Context:     strconv.Itoa(j),
					Content:     []*AddressAssertionSection{assertions[l]},
				})
			}
		}
		for j := 0; j < nof; j++ {
			//TODO CFE extend this test when we support multiple types per assertion
			for l := 0; l < 1405; l++ {
				zones = append(zones, &AddressZoneSection{
					SubjectAddr: subjectAddress2,
					Context:     strconv.Itoa(j),
					Content:     []*AddressAssertionSection{assertions[l]},
				})
			}
		}
	}
	zones = append(zones, zones[len(zones)-1]) //equals
	return zones
}

func sortedAddressQueries(nof int) []*AddressQuerySection {
	if nof > 9 {
		log.Error("nof must be smaller than 10", "nof", nof)
		//otherwise subjectAddr first value is now 2 digit and in string comparison "10." sorts before "2.",
		//which makes the test much more complicated
		nof = 9
	}
	queries := []*AddressQuerySection{}
	for i := 1; i < nof+1; i++ {
		//We start from 1 as leading zero's are omitted in IPv6 format while there are present in ipv4.
		//Thus leading zero is a special case. Where IPv6 are sorted before IPv4.
		_, subjectAddress, _ := net.ParseCIDR(fmt.Sprintf("%d.0.0.1/32", i))
		_, subjectAddress2, _ := net.ParseCIDR(fmt.Sprintf("%d::/64", i))
		for j := 0; j < nof; j++ {
			for k := 0; k < 13; k++ {
				for l := 0; l < nof; l++ {
					for m := 0; m < 8; m++ {
						//TODO CFE extend this test when we support multiple types per assertion
						queries = append(queries, &AddressQuerySection{
							SubjectAddr: subjectAddress,
							Context:     strconv.Itoa(j),
							Types:       []ObjectType{ObjectType(k)},
							Expires:     int64(l),
							Options:     []QueryOption{QueryOption(m)},
						})
					}
					for m := 0; m < 7; m++ {
						for n := m + 1; n < 8; n++ {
							//TODO CFE extend this test when we support multiple types per assertion
							queries = append(queries, &AddressQuerySection{
								SubjectAddr: subjectAddress,
								Context:     strconv.Itoa(j),
								Types:       []ObjectType{ObjectType(k)},
								Expires:     int64(l),
								Options:     []QueryOption{QueryOption(m), QueryOption(n)},
							})
						}
					}
				}
			}
		}
		for j := 0; j < nof; j++ {
			for k := 0; k < 13; k++ {
				for l := 0; l < nof; l++ {
					for m := 0; m < 8; m++ {
						//TODO CFE extend this test when we support multiple types per assertion
						queries = append(queries, &AddressQuerySection{
							SubjectAddr: subjectAddress2,
							Context:     strconv.Itoa(j),
							Types:       []ObjectType{ObjectType(k)},
							Expires:     int64(l),
							Options:     []QueryOption{QueryOption(m)},
						})
					}
				}
			}
		}
	}
	queries = append(queries, queries[len(queries)-1])
	return queries
}

func sortedNotifications(nofNotifications int) []*NotificationSection {
	notifications := []*NotificationSection{}
	tokens := sortedTokens(nofNotifications)
	typeNumbers := []int{100, 399, 400, 403, 404, 413, 500, 501, 504}
	for i := 0; i < nofNotifications; i++ {
		nofTypes := nofNotifications
		if nofTypes > 9 {
			nofTypes = 9
		}
		for j := 0; j < nofTypes; j++ {
			for k := 0; k < nofNotifications; k++ {
				notifications = append(notifications, &NotificationSection{
					Token: tokens[i],
					Type:  NotificationType(typeNumbers[j]),
					Data:  strconv.Itoa(k),
				})
			}
		}
	}
	notifications = append(notifications, notifications[len(notifications)-1])
	return notifications
}

//nofTokens must be smaller than 256
func sortedTokens(nofTokens int) []Token {
	if nofTokens > 255 {
		log.Error("nofTokens must be smaller than 256", "nofTokens", nofTokens)
		return nil
	}
	tokens := []Token{}
	for i := 0; i < nofTokens; i++ {
		token := Token{}
		copy(token[:], []byte{byte(i)})
		tokens = append(tokens, token)
	}
	return tokens
}
