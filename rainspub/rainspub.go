package rainspub

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sort"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/protoParser"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
)

var msgFramer rainslib.MsgFramer

//InitRainspub initializes rainspub
func InitRainspub(configPath string) error {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, h))
	err := loadConfig(configPath)
	if err != nil {
		return err
	}
	err = loadPrivateKey(config.ZonePrivateKeyPath)
	if err != nil {
		return err
	}
	p := zoneFileParser.Parser{}
	parser = p
	signatureEncoder = p
	msgParser = new(protoParser.ProtoParserAndFramer)
	return nil
}

//PublishInformation does:
//1) loads all assertions from the rains zone file.
//2) groups assertions into shards
//3) signs the zone and all contained shards and assertions
//4) create a message containing the zone
//5) send the message to all rains servers specified in the config
func PublishInformation() error {
	assertions, err := loadAssertions()
	if err != nil {
		return err
	}

	//TODO CFE add additional sharding parameters to config/allow for different sharding strategies
	zone := groupAssertionsToShards(assertions[0].SubjectZone, assertions[0].Context, assertions)

	//TODO implement signing with airgapping
	err = signZone(zone, rainslib.Ed25519, zonePrivateKey)
	if err != nil {
		log.Warn("Was not able to sign zone.", "error", err)
		return err
	}

	msg, err := createRainsMessage(zone)
	if err != nil {
		log.Warn("Was not able to parse the zone to a rains message.", "error", err)
		return err
	}

	err = sendMsg(msg, len(assertions), len(zone.Content))
	if err != nil {
		log.Warn("Was not able to send signed zone.", "error", err)
		return err
	}
	return nil
}

//loadAssertions returns all assertions contained in the rains zone file or an error.
func loadAssertions() ([]*rainslib.AssertionSection, error) {
	file, err := ioutil.ReadFile(config.ZoneFilePath)
	if err != nil {
		log.Error("Was not able to read zone file", "path", config.ZoneFilePath)
		return nil, err
	}
	assertions, err := parser.Decode(file)
	if err != nil {
		log.Error("Was not able to parse zone file.", "error", err)
		return nil, err
	}
	return assertions, nil
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
			log.Error("assertion's subjectZone or context does not match with the zone's", "assertion", a)
		}
		if prevAssertionSubjectName != a.SubjectName {
			nameCount++
			prevAssertionSubjectName = a.SubjectName
		}
		if nameCount > config.MaxAssertionsPerShard {
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

//signZone signs the zone and all contained shards and assertions with the zone's private key.
//TODO CFE we should use 2 valid signatures to avoid traffic bursts when a signature expires.
func signZone(zone *rainslib.ZoneSection, keyAlgo rainslib.SignatureAlgorithmType, privateKey interface{}) error {
	if zone == nil {
		return errors.New("zone is nil")
	}
	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			Algorithm: keyAlgo,
			KeySpace:  rainslib.RainsKeySpace,
		},
		ValidSince: time.Now().Add(config.ZoneValidSince).Unix(),
		ValidUntil: time.Now().Add(config.ZoneValidUntil).Unix(),
	}
	if ok := rainsSiglib.SignSection(zone, privateKey, signature, signatureEncoder); !ok {
		return errors.New("Was not able to sign and add the signature")
	}
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *rainslib.ShardSection:
			err := signShard(sec, keyAlgo, privateKey)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("Zone contained unexpected type expected=*ShardSection actual=%T", sec)
		}
	}
	return nil
}

//signShard signs the shard and all contained assertions with the zone's private key.
//It removes the subjectZone and context after the signatures have been added.
//It returns an error if it was unable to sign the shard.
//TODO we should use 2 valid signatures to avoid traffic bursts when a signature expires.
func signShard(s *rainslib.ShardSection, keyAlgo rainslib.SignatureAlgorithmType, privateKey interface{}) error {
	if s == nil {
		return errors.New("shard is nil")
	}
	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			Algorithm: keyAlgo,
			KeySpace:  rainslib.RainsKeySpace,
		},
		ValidSince: time.Now().Add(config.ShardValidSince).Unix(),
		ValidUntil: time.Now().Add(config.ShardValidUntil).Unix(),
	}
	if ok := rainsSiglib.SignSection(s, privateKey, signature, signatureEncoder); !ok {
		return errors.New("Was not able to sign and add the signature")
	}
	s.Context = ""
	s.SubjectZone = ""
	err := signAssertions(s.Content, keyAlgo, privateKey)
	return err
}

//signAssertions signs all assertions with the zone's private key.
//It removes the subjectZone and context after the signatures have been added.
//It returns an error if it was unable to sign the assertion.
//TODO we should use 2 valid signatures to avoid traffic bursts when a signature expires.
func signAssertions(assertions []*rainslib.AssertionSection, keyAlgo rainslib.SignatureAlgorithmType, privateKey interface{}) error {
	for _, a := range assertions {
		if a == nil {
			return errors.New("assertion is nil")
		}
		//TODO CFE handle multiple types per assertion
		signature := rainslib.Signature{
			PublicKeyID: rainslib.PublicKeyID{
				Algorithm: keyAlgo,
				KeySpace:  rainslib.RainsKeySpace,
			},
		}
		if a.Content[0].Type == rainslib.OTDelegation {
			signature.ValidSince = time.Now().Add(config.DelegationValidSince).Unix()
			signature.ValidUntil = time.Now().Add(config.DelegationValidUntil).Unix()
		} else {
			signature.ValidSince = time.Now().Add(config.AssertionValidSince).Unix()
			signature.ValidUntil = time.Now().Add(config.AssertionValidUntil).Unix()
		}

		if ok := rainsSiglib.SignSection(a, privateKey, signature, signatureEncoder); !ok {
			return errors.New("Was not able to sign and add the signature")
		}
		a.Context = ""
		a.SubjectZone = ""
	}
	return nil
}

//createRainsMessage creates a rainsMessage containing the given zone and return the byte representation of this rainsMessage ready to send out.
func createRainsMessage(zone *rainslib.ZoneSection) ([]byte, error) {
	msg := rainslib.RainsMessage{Token: rainslib.GenerateToken(), Content: []rainslib.MessageSection{zone}} //no capabilities
	byteMsg, err := msgParser.Encode(msg)
	if err != nil {
		return []byte{}, err
	}
	return byteMsg, nil
}

//sendMsg sends the given zone to rains servers specified in the configuration
func sendMsg(msg []byte, assertionCount, shardCount int) error {
	//TODO CFE use certificate for tls
	var conns []net.Conn
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	for _, server := range config.ServerAddresses {
		switch server.Type {
		case rainslib.TCP:
			conn, err := tls.Dial(server.TCPAddr.Network(), server.String(), conf)
			if err != nil {
				log.Error("Was not able to establish a connection.", "server", server, "error", err)
				continue
			}
			conns = append(conns, conn)
			msgFramer = new(protoParser.ProtoParserAndFramer)
			msgFramer.InitStreams(conn, conn)
			token, _ := msgParser.Token(msg)
			go listen(conn, token)
			err = msgFramer.Frame(msg)
			if err != nil {
				conn.Close()
				return err
			}
			log.Info("Published information.", "serverAddresses", server.String(), "#Assertions",
				assertionCount, "#Shards", shardCount)
		default:
			return fmt.Errorf("unsupported connection information type. actual=%v", server.Type)
		}
	}
	time.Sleep(2 * time.Second)
	for _, conn := range conns {
		conn.Close()
		log.Debug("connection closed")
	}
	return nil
}

//listen receives incoming messages. If the message's token matches the query's token, it handles
//the response.
func listen(conn net.Conn, token rainslib.Token) {
	for msgFramer.DeFrame() {
		_, err := msgParser.Token(msgFramer.Data())
		if err != nil {
			log.Warn("Was not able to extract the token", "message", hex.EncodeToString(msgFramer.Data()), "error", err)
			continue
		}
		msg, err := msgParser.Decode(msgFramer.Data())
		if err != nil {
			log.Warn("Was not able to decode received message", "message", hex.EncodeToString(msgFramer.Data()), "error", err)
			continue
		}
		//Rainspub only accepts notification messages in response to published information.
		if n, ok := msg.Content[0].(*rainslib.NotificationSection); ok && n.Token == token {
			if handleResponse(conn, msg.Content[0].(*rainslib.NotificationSection)) {
				conn.Close()
				return
			}
			continue
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

//capabilityIsHash returns true if capabilities are represented as a hash.
func capabilityIsHash(capabilities string) bool {
	return !strings.HasPrefix(capabilities, "urn:")
}
