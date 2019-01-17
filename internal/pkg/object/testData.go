package object

import (
	"strconv"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"golang.org/x/crypto/ed25519"
)

const (
	ip4TestAddr = "192.0.2.0"
	ip6TestAddr = "2001:db8::"
	testDomain  = "example.com"
)

//AllObjects returns all objects with valid content
func AllObjects() []Object {
	ip6Object := Object{Type: OTIP6Addr, Value: ip6TestAddr}
	ip4Object := Object{Type: OTIP4Addr, Value: ip4TestAddr}
	redirObject := Object{Type: OTRedirection, Value: testDomain}
	delegObject := Object{Type: OTDelegation, Value: PublicKey()}
	nameSetObject := Object{Type: OTNameset, Value: NamesetExpr("Would be an expression")}
	registrarObject := Object{Type: OTRegistrar, Value: "Registrar information"}
	registrantObject := Object{Type: OTRegistrant, Value: "Registrant information"}
	infraObject := Object{Type: OTInfraKey, Value: PublicKey()}
	extraObject := Object{Type: OTExtraKey, Value: PublicKey()}
	nextPublicKey := PublicKey()
	nextPublicKey.ValidSince = 10000
	nextPublicKey.ValidUntil = 50000
	nextKey := Object{Type: OTNextKey, Value: nextPublicKey}
	return []Object{NameObject(), ip6Object, ip4Object, redirObject, delegObject,
		nameSetObject, CertificateObject(), ServiceObject(), registrarObject,
		registrantObject, infraObject, extraObject, nextKey}
}

//NameObject returns a name object with valid content
func NameObject() Object {
	nameObjectContent := Name{
		Name:  testDomain,
		Types: []Type{OTIP4Addr, OTIP6Addr},
	}
	return Object{Type: OTName, Value: nameObjectContent}
}

//Certificate returns a certificate object with valid content
func CertificateObject() Object {
	certificate := Certificate{
		Type:     PTTLS,
		HashAlgo: algorithmTypes.Sha256,
		Usage:    CUEndEntity,
		Data:     []byte("certData"),
	}
	return Object{Type: OTCertInfo, Value: certificate}
}

//ServiceObject returns a service information object with valid content
func ServiceObject() Object {
	serviceInfo := ServiceInfo{
		Name:     "srvName",
		Port:     49830,
		Priority: 1,
	}
	return Object{Type: OTServiceInfo, Value: serviceInfo}
}

//PublicKey returns a public key with a freshly generated public key and valid content
func PublicKey() keys.PublicKey {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	return keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			KeyPhase:  0,
			Algorithm: algorithmTypes.Ed25519,
		},
		Key: pubKey,
	}
}

func SortedObjects(nofObj int) []Object {
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
				value = NamesetExpr(strconv.Itoa(j))
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
				Type:  Type(i + 1),
				Value: value,
			})
		}
	}
	return objects
}

func sortedNameObjects(nof int) []Name {
	objects := []Name{}
	for i := 0; i < nof; i++ {
		objTypes := nof
		if objTypes > 13 {
			objTypes = 13
		}
		for j := 0; j < objTypes; j++ {
			objects = append(objects, Name{Name: strconv.Itoa(i), Types: []Type{Type(j)}})
		}
		for j := 0; j < objTypes-1; j++ { //-1 to make sure that there are always 2 elements in the slice
			for k := j + 1; k < objTypes; k++ {
				objects = append(objects, Name{Name: strconv.Itoa(i), Types: []Type{Type(j), Type(k)}})
			}
		}
	}
	objects = append(objects, objects[len(objects)-1])
	return objects
}

func sortedPublicKeys(nof int) []keys.PublicKey {
	if nof > 255 {
		log.Error("nof must be smaller than 256", "nof", nof)
		nof = 255
	}
	pkeys := []keys.PublicKey{}
	for i := 1; i < 5; i++ {
		for j := 0; j < 1; j++ {
			for k := 0; k < nof; k++ {
				for l := 0; l < nof; l++ {
					for m := 0; m < nof; m++ {
						pkeys = append(pkeys, keys.PublicKey{
							PublicKeyID: keys.PublicKeyID{
								Algorithm: algorithmTypes.Signature(i),
								KeySpace:  keys.KeySpaceID(j),
							},
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

func sortedCertificates(nof int) []Certificate {
	if nof > 255 {
		log.Error("nof must be smaller than 256", "nof", nof)
		nof = 255
	}
	certs := []Certificate{}
	for i := 0; i < 2; i++ {
		for j := 2; j < 4; j++ {
			for k := 0; k < 4; k++ {
				for l := 0; l < nof; l++ {
					certs = append(certs, Certificate{
						Type:     ProtocolType(i),
						Usage:    CertificateUsage(j),
						HashAlgo: algorithmTypes.Hash(k),
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
