package rainsd

import (
	"rains/rainslib"

	log "github.com/inconshreveable/log15"
)

//Notify handles incoming notification messages
func Notify(body rainslib.NotificationBody, sender ConnInfo) {
	log.Info("Handle Notification", "NotificationBody", body)
	switch body.Type {
	case rainslib.Heartbeat:
		//Do nothing
	case rainslib.CapHashNotKnown:
		log.Info("Capability Hash was not understood", "token", body.Token)
		//TODO CFE send a full capabilities list on the next message it sends to the peer
		//store in a map key <dest> value <capabilities>. Before a message is parsed to CBOR format check if it must include capabilities.
	case rainslib.RcvMalformatMsg:
		log.Error("Msg malformated", "data", body.Data)
	case rainslib.RcvInconsistentMsg:
		log.Error("Msg inconsistent", "data", body.Data)
	case rainslib.MsgTooLarge:
		log.Info("Msg is too large", "token", body.Token, "data", body.Data)
		//TODO handle this case properly
	case rainslib.NoAssertionsExist:
		log.Info("No assertion exists. Query is unanswerable.", "Token", body.Token)
	case rainslib.UnspecServerErr:
		log.Error("Unspecified server error", "data", body.Data)
	case rainslib.ServerNotCapable:
		log.Error("Server not capable", "data", body.Data)
	case rainslib.NoAssertionAvail:
	//TODO CFE why/when is this notification message useful?
	default:
		log.Warn("No matching notification type")
	}
}
