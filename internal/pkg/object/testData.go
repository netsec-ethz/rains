package object

import (
	"fmt"
	"net"
	"strconv"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"golang.org/x/crypto/ed25519"
)

var (
	ip4TestAddr         = net.ParseIP("192.0.2.0")
	ip6TestAddr         = net.ParseIP("2001:db8::")
	scionip4TestAddr, _ = ParseSCIONAddress("1-ff00:0:111,[192.0.2.0]")
	scionip6TestAddr, _ = ParseSCIONAddress("1-ff00:0:111,[2001:db8::]")
	testDomain          = "example.com"
)

// AllObjects returns all objects with valid content
func AllObjects() []Object {
	ip6Object := Object{Type: OTIP6Addr, Value: ip6TestAddr}
	ip4Object := Object{Type: OTIP4Addr, Value: ip4TestAddr}
	scionip6Object := Object{Type: OTScionAddr, Value: scionip6TestAddr}
	scionip4Object := Object{Type: OTScionAddr, Value: scionip4TestAddr}
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
		registrantObject, infraObject, extraObject, nextKey, scionip6Object, scionip4Object}
}

// NameObject returns a name object with valid content
func NameObject() Object {
	nameObjectContent := Name{
		Name:  testDomain,
		Types: []Type{OTIP4Addr, OTIP6Addr, OTScionAddr},
	}
	return Object{Type: OTName, Value: nameObjectContent}
}

// Certificate returns a certificate object with valid content
func CertificateObject() Object {
	certificate := Certificate{
		Type:     PTTLS,
		HashAlgo: algorithmTypes.Sha256,
		Usage:    CUEndEntity,
		Data:     []byte("certData"),
	}
	return Object{Type: OTCertInfo, Value: certificate}
}

// ServiceObject returns a service information object with valid content
func ServiceObject() Object {
	serviceInfo := ServiceInfo{
		Name:     "srvName",
		Port:     49830,
		Priority: 1,
	}
	return Object{Type: OTServiceInfo, Value: serviceInfo}
}

// PublicKey returns a public key with a freshly generated public key and valid content
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

func SortedObjects() []Object {
	// Note: nofObjects should be more than 10, to test that things that should
	// sort numerically are not actually just sorted lexicographically (which is
	// the same for 0-9).
	nofObj := 17
	objects := []Object{}

	strings := sortedStrings(nofObj)
	nos := sortedNameObjects(nofObj)
	ip4s := sortedIPv4(nofObj)
	ip6s := sortedIPv6(nofObj)
	scAddrs := sortedSCIONAddr(nofObj)
	pkeys := sortedPublicKeys(nofObj)
	certs := sortedCertificates(nofObj)
	sis := sortedServiceInfo(nofObj)
	for t := OTName; t <= OTScionAddr; t++ {
		for j := 0; j < nofObj; j++ {
			var value interface{}
			switch t {
			case OTName:
				value = nos[j]
			case OTIP6Addr:
				value = ip6s[j] //ip6
			case OTIP4Addr:
				value = ip4s[j] //ip4
			case OTRedirection:
				value = strings[j] //redir
			case OTDelegation:
				value = pkeys[j]
			case OTNameset:
				value = NamesetExpr(strings[j])
			case OTCertInfo:
				value = certs[j]
			case OTServiceInfo:
				value = sis[j]
			case OTRegistrar:
				value = strings[j] //registrar
			case OTRegistrant:
				value = strings[j] //registrant
			case OTInfraKey:
				value = pkeys[j]
			case OTExtraKey:
				value = pkeys[j]
			case OTNextKey:
				value = pkeys[j]
			case OTScionAddr:
				value = scAddrs[j]
			default:
				panic("missing case")
			}
			objects = append(objects, Object{
				Type:  t,
				Value: value,
			})
		}
	}
	return objects
}

func sortedStrings(nof int) []string {
	if nof > 100 {
		panic("not sorted for nof > 100, need to increase field width")
	}
	objects := make([]string, nof)
	for i := 0; i < nof; i++ {
		objects[i] = fmt.Sprintf("%02d", i)
	}
	return objects
}

func sortedNameObjects(nof int) []Name {
	objects := []Name{}
	for i := 0; i < nof; i++ {
		objTypes := nof
		if objTypes > 15 {
			objTypes = 15
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
		panic("nof must be smaller than 256")
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
		panic("nof must be smaller than 256")
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

func sortedIPv4(nof int) []net.IP {
	if nof > 255 {
		panic("nof must be smaller than 256")
	}
	ips := []net.IP{}
	for i := 0; i < nof; i++ {
		ips = append(ips, net.ParseIP(fmt.Sprintf("0.0.0.%d", i)))
	}
	return ips
}

func sortedIPv6(nof int) []net.IP {
	ips := []net.IP{}
	for i := 0; i < nof; i++ {
		ips = append(ips, net.ParseIP(fmt.Sprintf("::f00:c00:%x", i)))
	}
	return ips
}

func sortedSCIONAddr(nof int) []*SCIONAddress {
	addrs := []*SCIONAddress{}
	i := 0
	for ; i < nof/2; i++ {
		a, _ := ParseSCIONAddress(fmt.Sprintf("1-ffaa:1:1,[::f00:c00:%x]", i))
		addrs = append(addrs, a)
	}
	for ; i < nof; i++ {
		a, _ := ParseSCIONAddress(fmt.Sprintf("1-ffaa:1:1,[10.0.0.%d]", i))
		addrs = append(addrs, a)
	}
	return addrs
}
