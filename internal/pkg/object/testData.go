package object

import (
	"fmt"
	"net"
	"strconv"

	"github.com/scionproto/scion/go/lib/snet"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"golang.org/x/crypto/ed25519"
)

var (
	ip4TestAddr      = net.ParseIP("192.0.2.0")
	ip6TestAddr      = net.ParseIP("2001:db8::")
	sAddr4, _        = snet.AddrFromString("1-ff00:0:111,[192.0.2.0]")
	scionip4TestAddr = &SCIONAddress{IA: sAddr4.IA, Host: sAddr4.Host.L3}
	sAddr6, _        = snet.AddrFromString("1-ff00:0:111,[2001:db8::]")
	scionip6TestAddr = &SCIONAddress{IA: sAddr6.IA, Host: sAddr6.Host.L3}
	testDomain       = "example.com"
)

//AllObjects returns all objects with valid content
func AllObjects() []Object {
	ip6Object := Object{Type: OTIP6Addr, Value: ip6TestAddr}
	ip4Object := Object{Type: OTIP4Addr, Value: ip4TestAddr}
	scionip6Object := Object{Type: OTScionAddr6, Value: scionip6TestAddr}
	scionip4Object := Object{Type: OTScionAddr4, Value: scionip4TestAddr}
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

//NameObject returns a name object with valid content
func NameObject() Object {
	nameObjectContent := Name{
		Name:  testDomain,
		Types: []Type{OTIP4Addr, OTIP6Addr, OTScionAddr4, OTScionAddr6},
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
	if nofObj > 15 {
		nofObj = 15
	}
	nos := sortedNameObjects(nofObj)
	ip4s := sortedIPv4(nofObj)
	ip6s := sortedIPv6(nofObj)
	scAddr4s := sortedSCIONAddr4(nofObj)
	scAddr6s := sortedSCIONAddr6(nofObj)
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
				value = ip6s[j] //ip6
			case 2:
				value = ip4s[j] //ip4
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
			case 14:
				value = scAddr6s[j] // scionip6
			case 15:
				value = scAddr4s[j] // scionip4

			}
			objects = append(objects, Object{
				Type:  Type(i + 1),
				Value: value,
			})
		}
	}
	fmt.Printf("%v", objects)
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

func sortedIPv4(nof int) []net.IP {
	ips := []net.IP{}
	for i := 0; i < nof; i++ {
		ips = append(ips, net.ParseIP(fmt.Sprintf("0.0.0.%d", i)))
	}
	return ips
}

func sortedIPv6(nof int) []net.IP {
	ips := []net.IP{}
	for i := 0; i < nof; i++ {
		ips = append(ips, net.ParseIP(fmt.Sprintf("::ffff:0.0.0.%d", i)))
	}
	return ips
}

func sortedSCIONAddr4(nof int) []*SCIONAddress {
	addrs := []*SCIONAddress{}
	for i := 0; i < nof; i++ {
		a, _ := snet.AddrFromString(fmt.Sprintf("1-ffaa:1:1,[1.1.1.%d]", i))
		addrs = append(addrs, &SCIONAddress{IA: a.IA, Host: a.Host.L3})
	}
	return addrs
}

func sortedSCIONAddr6(nof int) []*SCIONAddress {
	addrs := []*SCIONAddress{}
	for i := 0; i < nof; i++ {
		a, _ := snet.AddrFromString(fmt.Sprintf("1-ffaa:1:1,[::ffff:0.0.0.%d]", i))
		addrs = append(addrs, &SCIONAddress{IA: a.IA, Host: a.Host.L3})
	}
	return addrs
}
