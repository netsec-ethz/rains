package rainspub

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/protoParser"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
	"golang.org/x/crypto/ed25519"
)

//signatureEncoder is used to encode a section such that it can be signed
var signatureEncoder rainslib.SignatureFormatEncoder

//SignSectionUnsafe signs section and all contained sections (if it is a shard or zone). The
//signature meta data must already be present. SignSectionUnsafe returns an error if it was not able
//to sign the section and all contained sections. The section is signed as is. The Caller must make
//sure that the section is sorted and adheres to the protocol and policies.
func SignSectionUnsafe(section rainslib.MessageSectionWithSig, keyPhaseToPath map[int]string) error {
	var privateKeys map[int]interface{}
	for keyPhase, path := range keyPhaseToPath {
		privateKey, err := loadPrivateKey(path)
		if err != nil {
			return err
		}
		privateKeys[keyPhase] = privateKey
	}
	signatureEncoder = zoneFileParser.Parser{}
	//TODO implement signing with airgapping
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		return signAssertion(section, privateKeys)
	case *rainslib.ShardSection:
		return signShard(section, privateKeys)
	case *rainslib.ZoneSection:
		return signZone(section, privateKeys)
	case *rainslib.AddressAssertionSection:
		log.Warn("Signing address assertions not yet implemented")
		return errors.New("Signing address assertions not yet implemented")
	}
	return nil
}

//loadPrivateKey loads the zone private key
//TODO CFE remove when we have air gapping
func loadPrivateKey(privateKeyPath string) (ed25519.PrivateKey, error) {
	privKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.Error("Was not able to read privateKey", "path", privateKeyPath, "error", err)
		return nil, err
	}
	privateKey := make([]byte, hex.DecodedLen(len(privKey)))
	i, err := hex.Decode(privateKey, privKey)
	if err != nil {
		log.Error("Was not able to decode privateKey", "path", privateKeyPath, "error", err)
		return nil, err
	}
	if i != ed25519.PrivateKeySize {
		log.Error("Private key length is incorrect", "expected", ed25519.PrivateKeySize, "actual", i)
		return nil, errors.New("Private key length is incorrect")
	}
	return privateKey, nil
}

//signZone signs the zone and all contained shards and assertions with the zone's private key. It
//removes the subjectZone and context of the contained assertions and shards after the signatures
//have been added. It returns an error if it was unable to sign the zone or any of the contained
//shards and assertions.
func signZone(zone *rainslib.ZoneSection, privateKeys map[int]interface{}) error {
	if zone == nil {
		return errors.New("zone is nil")
	}
	for _, sig := range zone.Signatures {
		if ok := rainsSiglib.SignSectionUnsafe(zone, privateKeys[sig.KeyPhase], sig, signatureEncoder); !ok {
			log.Error("Was not able to sign and add the signature", "zone", zone, "signature", sig)
			return errors.New("Was not able to sign and add the signature")
		}
	}
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *rainslib.AssertionSection:
			if err := signAssertion(sec, privateKeys); err != nil {
				return err
			}
			sec.Context = ""
			sec.SubjectZone = ""
		case *rainslib.ShardSection:
			if err := signShard(sec, privateKeys); err != nil {
				return err
			}
			sec.Context = ""
			sec.SubjectZone = ""
		default:
			return fmt.Errorf("Zone contained unexpected type expected *ShardSection or *AssertionSection actual=%T", sec)
		}
	}
	return nil
}

//signShard signs the shard and all contained assertions with the zone's private key. It removes the
//subjectZone and context of the contained assertions after the signatures have been added. It
//returns an error if it was unable to sign the shard or any of the assertions.
func signShard(s *rainslib.ShardSection, privateKeys map[int]interface{}) error {
	if s == nil {
		return errors.New("shard is nil")
	}
	for _, sig := range s.Signatures {
		if ok := rainsSiglib.SignSectionUnsafe(s, privateKeys[sig.KeyPhase], sig, signatureEncoder); !ok {
			log.Error("Was not able to sign and add the signature", "shard", s, "signature", sig)
			return errors.New("Was not able to sign and add the signature")
		}
	}
	for _, a := range s.Content {
		if err := signAssertion(a, privateKeys); err != nil {
			return err
		}
		a.Context = ""
		a.SubjectZone = ""
	}
	return nil
}

//signAssertion computes the signature data for all contained signatures.
//It returns an error if it was unable to create all signatures on the assertion.
func signAssertion(a *rainslib.AssertionSection, privateKeys map[int]interface{}) error {
	if a == nil {
		return errors.New("assertion is nil")
	}
	for _, sig := range a.Signatures {
		if ok := rainsSiglib.SignSectionUnsafe(a, privateKeys[sig.KeyPhase], sig, signatureEncoder); !ok {
			log.Error("Was not able to sign and add the signature", "assertion", a, "signature", sig)
			return errors.New("Was not able to sign and add the signature")
		}
	}
	return nil
}

//PublishSections establishes connections to all rains servers mentioned in conns. It then sends
//sections to all of them. It returns the connection information of those servers it was not able to
//push sections, otherwise nil is returned.
func PublishSections(sections []byte, conns []rainslib.ConnInfo) []rainslib.ConnInfo {
	var errorConns []rainslib.ConnInfo
	results := make(chan *rainslib.ConnInfo, len(conns))
	for _, conn := range conns {
		go connectAndSendMsg(sections, conn, results)
	}
	for i := 0; i < len(conns); i++ {
		if errorConn := <-results; errorConn != nil {
			errorConns = append(errorConns, *errorConn)
		}
	}
	return errorConns
}

//connectAndSendMsg establishes a connection to server and sends msg. It returns the server info on
//the result channel if it was not able to send the whole msg to it, else nil.
func connectAndSendMsg(msg []byte, server rainslib.ConnInfo, result chan<- *rainslib.ConnInfo) {
	//TODO CFE use certificate for tls
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	switch server.Type {
	case rainslib.TCP:
		conn, err := tls.Dial(server.TCPAddr.Network(), server.String(), conf)
		if err != nil {
			log.Error("Was not able to establish a connection.", "server", server, "error", err)
			result <- &server
			return
		}

		msgFramer := new(protoParser.ProtoParserAndFramer)
		msgFramer.InitStreams(conn, conn)
		token, _ := msgFramer.Token(msg)
		success := make(chan bool)
		go listen(msgFramer, conn, token, success)
		err = msgFramer.Frame(msg)
		if err != nil {
			conn.Close()
			log.Error("Was not able to frame the message.", "msg", msg, "server", server, "error", err)
			result <- &server
			return
		}

		if <-success {
			log.Debug("Successful published information.", "serverAddresses", server.String())
			result <- nil
		} else {
			result <- &server
		}
	default:
		log.Error("Unsupported connection information type.", "connType", server.Type)
		result <- &server
	}
}

//listen receives incoming messages for one second. If the message's token matches the query's
//token, it handles the response.
func listen(msgFramer *protoParser.ProtoParserAndFramer, conn net.Conn, token rainslib.Token, success chan<- bool) {
	//close connection after 1 second assuming everything went well
	deadline := make(chan bool)
	result := make(chan bool)
	go func() {
		time.Sleep(time.Second)
		deadline <- true
	}()
	go waitForResponse(msgFramer, conn, token, result)
	for true {
		select {
		case <-deadline:
			conn.Close()
			success <- true
			return
		case err := <-result:
			if err {
				success <- false
			} else {
				go waitForResponse(msgFramer, conn, token, result)
			}
		}
	}

}

func waitForResponse(msgFramer *protoParser.ProtoParserAndFramer, conn net.Conn,
	token rainslib.Token, serverError chan<- bool) {
	for msgFramer.DeFrame() {
		_, err := msgFramer.Token(msgFramer.Data())
		if err != nil {
			log.Warn("Was not able to extract the token", "message", hex.EncodeToString(msgFramer.Data()), "error", err)
			serverError <- false
			return
		}
		msg, err := msgFramer.Decode(msgFramer.Data())
		if err != nil {
			log.Warn("Was not able to decode received message", "message", hex.EncodeToString(msgFramer.Data()), "error", err)
			serverError <- false
			return
		}
		//Rainspub only accepts notification messages in response to published information.
		if n, ok := msg.Content[0].(*rainslib.NotificationSection); ok && n.Token == token {
			if handleResponse(conn, msg.Content[0].(*rainslib.NotificationSection)) {
				conn.Close()
				serverError <- true
				return
			}
			serverError <- false
			return
		}
		log.Debug("Token of sent message does not match the token of the received message",
			"messageToken", token, "recvToken", msg.Token)
	}
}

//handleResponse handles the received notification message and returns true if the connection can
//be closed.
func handleResponse(conn net.Conn, n *rainslib.NotificationSection) bool {
	switch n.Type {
	case rainslib.NTHeartbeat, rainslib.NTNoAssertionsExist, rainslib.NTNoAssertionAvail:
	//nop
	case rainslib.NTCapHashNotKnown:
	//TODO CFE send back the whole capability list in an empty message
	case rainslib.NTBadMessage:
		log.Error("Sent msg was malformed", "data", n.Data)
	case rainslib.NTRcvInconsistentMsg:
		log.Error("Sent msg was inconsistent", "data", n.Data)
	case rainslib.NTMsgTooLarge:
		log.Error("Sent msg was too large", "data", n.Data)
		//What should we do in this case. apparently it is not possible to send a zone because
		//it is too large. send shards instead?
	case rainslib.NTUnspecServerErr:
		log.Error("Unspecified error of other server", "data", n.Data)
		//TODO CFE resend?
	case rainslib.NTServerNotCapable:
		log.Error("Other server was not capable", "data", n.Data)
		//TODO CFE when can this occur?
	default:
		log.Error("Received non existing notification type")
	}
	return false
}
