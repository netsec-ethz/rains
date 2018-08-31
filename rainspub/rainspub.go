package rainspub

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sort"
	"strconv"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/protoParser"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
	"golang.org/x/crypto/ed25519"
)

//Init starts the zone information publishing process according to the provided config.
func Init(inputConfig Config) {
	config = inputConfig
	publish()
}

//publish calls the relevant library function to publish information according to the provided
//config during initialization.
func publish() {
	_, err := loadZonefile()
	if err != nil {
		return
	}
	_, err = loadPrivateKeys()
	if err != nil {
		return
	}
	if config.DoSharding {
		//groupAssertionsToShards
	}
	if config.AddSignatureMetaData {
		//addSignatureMetaData()
	}
	if config.DoConsistencyCheck {
		//consistencyCheck()
	}
	if config.SortShards {
		//sort shards
	}
	if config.DoSigning {
		//UnsafeSign()
	}
	if config.SignAssertions {
		//UnsafeSign()
	}
	if config.SignShards {
		//UnsafeSign()
	}
	if config.OutputPath != "" {
		//write zonefile
	}
	if config.DoPublish {
		//publish to authoritative servers
	}
}

//loadZonefile loads the zonefile from disk.
func loadZonefile() ([]rainslib.MessageSectionWithSigForward, error) {
	file, err := ioutil.ReadFile(config.ZonefilePath)
	if err != nil {
		log.Error("Was not able to read zone file", "path", config.ZonefilePath)
		return nil, err
	}
	//FIXME CFE replace with call to yacc generated zonefile parser.
	zone, err := parser.DecodeZone(file)
	if err != nil {
		log.Error("Was not able to parse zone file.", "error", err)
		return nil, err
	}
	return []rainslib.MessageSectionWithSigForward{zone}, nil
}

//loadPrivateKeys reads private keys from the path provided in the config and returns a map from
//keyphase to ed25519 private key.
func loadPrivateKeys() (map[int]ed25519.PrivateKey, error) {
	//FIXME CFE should also contain the type of the private key, add PrivateKeyObject
	var input map[string][]byte
	file, err := ioutil.ReadFile(config.PrivateKeyPath)
	if err != nil {
		log.Error("Could not open config file...", "path", config.PrivateKeyPath, "error", err)
		return nil, err
	}
	if err = json.Unmarshal(file, &input); err != nil {
		log.Error("Could not unmarshal json format of private keys", "error", err)
		return nil, err
	}
	var output map[int]ed25519.PrivateKey
	for key, value := range input {
		privateKey := make([]byte, hex.DecodedLen(len(value)))
		length, err := hex.Decode(privateKey, value)
		if err != nil {
			log.Error("Was not able to decode privateKey", "error", err)
			return nil, err
		}
		if length != ed25519.PrivateKeySize {
			log.Error("Private key length is incorrect", "expected", ed25519.PrivateKeySize,
				"actual", length)
			return nil, errors.New("incorrect private key length")
		}
		keyphase, err := strconv.Atoi(key)
		if err != nil {
			log.Error("Was not able to convert keyphase to int", "error", err)
			return nil, err
		}
		output[keyphase] = ed25519.PrivateKey(privateKey)
	}
	return output, nil
}

//groupAssertionsToShards creates shards containing a maximum number of different assertion names
//according to the configuration. Before grouping the assertions, it sorts them. It returns a zone
//section containing the created shards. The contained shards and assertions still have non empty
//subjectZone and context values as these values are needed to generate a signatures
func groupAssertionsToShards(subjectZone, context string, assertions []*rainslib.AssertionSection) *rainslib.ZoneSection {
	//the assertion compareTo function sorts first by subjectName. Thus we can use it here.
	sort.Slice(assertions, func(i, j int) bool { return assertions[i].CompareTo(assertions[j]) < 0 })
	shards := []rainslib.MessageSectionWithSigForward{}
	nameCount := 0
	prevAssertionSubjectName := ""
	prevShardAssertionSubjectName := ""
	shard := newShard(subjectZone, context)
	for i, a := range assertions {
		if a.SubjectZone != subjectZone || a.Context != context {
			//log.Error("assertion's subjectZone or context does not match with the zone's", "assertion", a)
		}
		if prevAssertionSubjectName != a.SubjectName {
			nameCount++
			prevAssertionSubjectName = a.SubjectName
		}
		if nameCount > config.NofAssertionsPerShard {
			shard.RangeFrom = prevShardAssertionSubjectName
			shard.RangeTo = a.SubjectName
			shards = append(shards, shard)
			nameCount = 1
			shard = newShard(subjectZone, context)
			prevShardAssertionSubjectName = assertions[i-1].SubjectName
		}
		shard.Content = append(shard.Content, a)
	}
	shard.RangeFrom = prevShardAssertionSubjectName
	shard.RangeTo = ""
	shards = append(shards, shard)

	section := &rainslib.ZoneSection{
		Context:     context,
		SubjectZone: subjectZone,
		Content:     shards,
	}
	return section
}

func newShard(subjectZone, context string) *rainslib.ShardSection {
	return &rainslib.ShardSection{
		SubjectZone: subjectZone,
		Context:     context,
		Content:     []*rainslib.AssertionSection{},
	}
}

//publishZone performs the following steps:
//1) Loads the rains zone file.
//2) Adds Signature MetaData and perform consistency checks on the zone and its
//   signatures
//3) Let rainspub sign the zone
//4) Query the superordinate zone for the new delegation and push it to all
//   rains servers
//5) After rainspub signed the zone, send the signed zone to all rains servers
//   specified in the config
//returns an error if something goes wrong
/*func publishZone(keyPhase int) error {

	//TODO CFE be able to add multiple signature to a section
	addSignatureMetaData(zone, keyPhase)
	if ConsistencyCheck(zone) {
		return errors.New("Inconsistent section")
	}
	//TODO CFE do this in a go routine
	if err = SignSectionUnsafe(zone, keyPhaseToPath); err != nil {
		return err
	}
	//TODO CFE: query new delegation from superordinate server and push them to all rains servers
	msg, err := CreateRainsMessage(zone)
	if err != nil {
		log.Warn("Was not able to parse the zone to a rains message.", "error", err)
		return err
	}
	connErrors := PublishSections(msg, config.ServerAddresses)
	for _, connErr := range connErrors {
		log.Warn("Was not able to send signed zone to this server.", "server", connErr.TCPAddr.String())
		//TODO CFE: Implement error handling
	}
	return nil
}
*/
//TODO CFE change it such that it can be used as envisioned in the
//design-scalable-signature-updates.md
//especially that not all assertions are expiring at the same time
func addSignatureMetaData(zone *rainslib.ZoneSection, keyPhase int) {
	//TODO CFE consider from config, validUntil, validSince, duration
	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			Algorithm: rainslib.Ed25519,
			KeySpace:  rainslib.RainsKeySpace,
			KeyPhase:  keyPhase,
		},
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Unix(),
	}
	zone.AddSig(signature)
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *rainslib.AssertionSection:
			if sec.Content[0].Type == rainslib.OTDelegation {
				signature.ValidSince = time.Now().Unix()
				signature.ValidUntil = time.Now().Unix()
			} else {
				signature.ValidSince = time.Now().Unix()
				signature.ValidUntil = time.Now().Unix()
			}
		case *rainslib.ShardSection:
			signature.ValidSince = time.Now().Unix()
			signature.ValidUntil = time.Now().Unix()
		default:
			log.Error("Invalid zone content")
		}
		sec.AddSig(signature)
	}
}

//consistencyCheck returns true if there are no inconsistencies in the section. It
//also makes sure that the section is sorted
func consistencyCheck(section rainslib.MessageSectionWithSig) bool {
	//TODO consider config.SigNotExpired and config.checkStringFields
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		return rainsSiglib.ValidSectionAndSignature(section)
	case *rainslib.ShardSection:
		return shardConsistencyCheck(section)
	case *rainslib.ZoneSection:
		if !rainsSiglib.ValidSectionAndSignature(section) {
			return false
		}
		for _, sec := range section.Content {
			switch sec := sec.(type) {
			case *rainslib.AssertionSection:
				if !rainsSiglib.ValidSectionAndSignature(sec) {
					return false
				}
			case *rainslib.ShardSection:
				if !shardConsistencyCheck(sec) {
					return false
				}
			default:
				log.Error("Invalid zone content", "zone", section)
				return false
			}
		}
	case *rainslib.AddressAssertionSection:
		log.Warn("Not yet implemented")
		return false
	default:
		log.Error("Invalid section type")
		return false
	}
	return true
}

//shardConsistencyCheck returns true if the shard and all contained
//assertions are consistent and sorted
func shardConsistencyCheck(shard *rainslib.ShardSection) bool {
	if !rainsSiglib.ValidSectionAndSignature(shard) {
		return false
	}
	for _, a := range shard.Content {
		if !rainsSiglib.ValidSectionAndSignature(a) {
			return false
		}
	}
	return true
}

//SignSectionUnsafe signs section and all contained sections (if it is a shard or zone). The
//signature meta data must already be present. SignSectionUnsafe returns an error if it was not able
//to sign the section and all contained sections. The section is signed as is. The Caller must make
//sure that the section is sorted and adheres to the protocol and policies.
func SignSectionUnsafe(section rainslib.MessageSectionWithSig, keyPhaseToPath map[int]string) error {
	//consider in config: keyphase, keyAlgorithm,
	var privateKeys map[int]interface{}
	for keyPhase, path := range keyPhaseToPath {
		privateKey, err := loadPrivateKey(path)
		if err != nil {
			return err
		}
		privateKeys[keyPhase] = privateKey
	}
	signatureEncoder := zoneFileParser.Parser{}
	//TODO implement signing with airgapping
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		return signAssertion(section, privateKeys, signatureEncoder)
	case *rainslib.ShardSection:
		return signShard(section, privateKeys, signatureEncoder)
	case *rainslib.ZoneSection:
		return signZone(section, privateKeys, signatureEncoder)
	case *rainslib.AddressAssertionSection:
		log.Warn("Signing address assertions not yet implemented")
		return errors.New("Signing address assertions not yet implemented")
	}
	return nil
}

//signZone signs the zone and all contained shards and assertions with the zone's private key. It
//removes the subjectZone and context of the contained assertions and shards after the signatures
//have been added. It returns an error if it was unable to sign the zone or any of the contained
//shards and assertions.
func signZone(zone *rainslib.ZoneSection, privateKeys map[int]interface{}, signatureEncoder rainslib.SignatureFormatEncoder) error {
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
			if err := signAssertion(sec, privateKeys, signatureEncoder); err != nil {
				return err
			}
			sec.Context = ""
			sec.SubjectZone = ""
		case *rainslib.ShardSection:
			if err := signShard(sec, privateKeys, signatureEncoder); err != nil {
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
func signShard(s *rainslib.ShardSection, privateKeys map[int]interface{}, signatureEncoder rainslib.SignatureFormatEncoder) error {
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
		if err := signAssertion(a, privateKeys, signatureEncoder); err != nil {
			return err
		}
		a.Context = ""
		a.SubjectZone = ""
	}
	return nil
}

//signAssertion computes the signature data for all contained signatures.
//It returns an error if it was unable to create all signatures on the assertion.
func signAssertion(a *rainslib.AssertionSection, privateKeys map[int]interface{}, signatureEncoder rainslib.SignatureFormatEncoder) error {
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

//CreateRainsMessage creates a rainsMessage containing the given zone and
//returns the byte representation of this rainsMessage ready to send out.
func CreateRainsMessage(zone *rainslib.ZoneSection) ([]byte, error) {
	msg := rainslib.RainsMessage{Token: rainslib.GenerateToken(), Content: []rainslib.MessageSection{zone}} //no capabilities
	msgParser := new(protoParser.ProtoParserAndFramer)
	byteMsg, err := msgParser.Encode(msg)
	if err != nil {
		return []byte{}, err
	}
	return byteMsg, nil
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
