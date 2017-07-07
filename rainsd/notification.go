package rainsd

import (
	"github.com/netsec-ethz/rains/rainslib"

	log "github.com/inconshreveable/log15"
)

//notify handles incoming notification messages
func notify(msgSender msgSectionSender) {
	notifLog := log.New("notificationMsgSection", msgSender.Section)
	switch msgSender.Section.(*rainslib.NotificationSection).Type {
	case rainslib.NTCapHashNotKnown:
		notifLog.Info("Capability Hash was not understood")
		//TODO CFE send a full capabilities list on the next message it sends to the peer (own capability are stored in config)
		//Change value in connection cache to also hold a list of capabilities. Then in SendTo() it gets connInfo and a list of capabilities. If caps not empty send them along
		//and set the value in the cache to conn, empty list
	case rainslib.NTBadMessage:
		notifLog.Error("Sent msg was malformed")
	case rainslib.NTRcvInconsistentMsg:
		notifLog.Error("Sent msg was inconsistent")
	case rainslib.NTMsgTooLarge:
		notifLog.Error("Sent msg was too large")
	case rainslib.NTNoAssertionsExist:
		notifLog.Info("Bad request, only clients receive this notification type")
		msg := rainslib.NewNotificationMessage(msgSender.Token, rainslib.NTBadMessage, "")
		SendMessage(msg, msgSender.Sender)
	case rainslib.NTUnspecServerErr:
		notifLog.Error("Unspecified error of other server")
	case rainslib.NTServerNotCapable:
		notifLog.Error("Other server was not capable")
	case rainslib.NTNoAssertionAvail:
		notifLog.Info("No assertion was available")
		//TODO CFE forward this msg to the query issuing it. Lookup token mapping in delegationTokenMapping
	default:
		notifLog.Warn("No matching notification type")
		msg := rainslib.NewNotificationMessage(msgSender.Token, rainslib.NTBadMessage, "No matching notification type")
		SendMessage(msg, msgSender.Sender)
	}
}
