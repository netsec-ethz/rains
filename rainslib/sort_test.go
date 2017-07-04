package rainslib

import (
	"strconv"

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
	for i := 0; i < nofObj; i++ {
		nos := sortedNameObjects(nofObj)
		pkeys := sortedPublicKeys(nofObj)
		certs := sortedCertificates(nofObj)
		sis := sortedServiceInfo(nofObj)
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
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for k := 0; k < nof; k++ {
				objs := sortedObjects(13)
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

func sortedShards(nofObj, nofAssertions, nofShards int) []*ShardSection {
	return []*ShardSection{}
}

func sortedZones(nofObj, nofAssertions, nofShards, nofZones int) []*ZoneSection {
	return []*ZoneSection{}
}

func sortedQueries(nofQueries, nofOptions int) []*QuerySection {
	return []*QuerySection{}
}

func sortedAddressAssertions(nofObj, nofAssertions int) []*AddressAssertionSection {
	return []*AddressAssertionSection{}
}

func sortedAddressZones(nofObj, nofAssertions, nofZones int) []*AddressZoneSection {
	return []*AddressZoneSection{}
}

func sortedAddressQueries(nofQueries, nofOptions int) []*AddressQuerySection {
	return []*AddressQuerySection{}
}

func sortedNotifications(nofNotifications int) []*NotificationSection {
	notifications := []*NotificationSection{}
	tokens := sortedTokens(nofNotifications)
	for i := 0; i < nofNotifications; i++ {
		nofTypes := nofNotifications
		if nofTypes > 9 {
			nofTypes = 9
		}
		for j := 0; j < nofTypes; j++ {
			for k := 0; k < nofNotifications; k++ {
				typeNumbers := []int{100, 399, 400, 403, 404, 413, 500, 501, 504}
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
