package rainsd

import (
	log "github.com/inconshreveable/log15"

	"rains/rainslib"
)

//notify handles incoming notification messages
func notify(msgSender msgSectionSender) {
	notifLog := log.New("notificationMsgSection", msgSender.Section)
	switch msgSender.Section.(*rainslib.NotificationSection).Type {
	case rainslib.CapHashNotKnown:
		notifLog.Info("Capability Hash was not understood")
		//TODO CFE send a full capabilities list on the next message it sends to the peer (own capability are stored in config)
		//Change value in connection cache to also hold a list of capabilities. Then in SendTo() it gets connInfo and a list of capabilities. If caps not empty send them along
		//and set the value in the cache to conn, empty list
	case rainslib.BadMessage:
		notifLog.Error("Sent msg was malformed")
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
		sendTo(msg, msgSender.Sender)
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
		sendTo(msg, msgSender.Sender)
	}
}
