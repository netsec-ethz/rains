package rainsd

import (
	"rains/rainslib"

	log "github.com/inconshreveable/log15"
)

//Notify handles incoming notification messages
func Notify(msgSender MsgSectionSender) {
	notifLog := log.New("NotificationMsgSection", msgSender.Msg)
	switch msgSender.Msg.(*rainslib.NotificationSection).Type {
	case rainslib.Heartbeat:
		//Do nothing
	case rainslib.CapHashNotKnown:
		notifLog.Info("Capability Hash was not understood")
		//TODO CFE send a full capabilities list on the next message it sends to the peer
		//store in a map key <dest> value <capabilities>. Before a message is parsed to CBOR format check if it must include capabilities.
	case rainslib.BadMessage:
		notifLog.Error("Sent msg was malformated")
	case rainslib.RcvInconsistentMsg:
		notifLog.Error("Sent msg was inconsistent")
	case rainslib.MsgTooLarge:
		notifLog.Error("Sent msg was too large")
	case rainslib.NoAssertionsExist:
		notifLog.Info("Bad request, only clients receive this notification type")
		msg, err := CreateNotificationMsg(msgSender.Token, rainslib.BadMessage, "")
		if err != nil {
			return
		}
		SendTo(msg, msgSender.Sender)
	case rainslib.UnspecServerErr:
		notifLog.Error("Unspecified error of other server")
	case rainslib.ServerNotCapable:
		notifLog.Error("Other server was not capable")
	case rainslib.NoAssertionAvail:
		notifLog.Info("No assertion was available")
		//TODO CFE forward this msg to the query issuing it. Lookup token mapping in delegationTokenMapping
	default:
		notifLog.Warn("No matching notification type")
		msg, err := CreateNotificationMsg(msgSender.Token, rainslib.BadMessage, "No matching notification type")
		if err != nil {
			return
		}
		SendTo(msg, msgSender.Sender)
	}
}
