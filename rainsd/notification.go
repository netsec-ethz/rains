package rainsd

import (
	"strings"

	"github.com/netsec-ethz/rains/rainslib"

	log "github.com/inconshreveable/log15"
)

//notify handles incoming notification messages
func notify(msgSender msgSectionSender) {
	notifLog := log.New("notificationMsgSection", msgSender.Section)
	section := msgSender.Section.(*rainslib.NotificationSection)
	switch section.Type {
	case rainslib.NTHeartbeat:
	//nop
	case rainslib.NTCapabilityAnswer:
		if len(section.Data) == 0 {
			log.Error("Received NTCapabilityAnswer without data")
			return
		}
		if capabilityIsHash(section.Data) {
			if caps, ok := capabilities.Get([]byte(section.Data)); ok {
				connCache.AddCapabilityList(msgSender.Sender, caps)
			} else {
				sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTCapHashNotKnown, "")
			}
		} else {
			cList := []rainslib.Capability{}
			for _, c := range strings.Split(section.Data, " ") {
				cList = append(cList, rainslib.Capability(c))
			}
			connCache.AddCapabilityList(msgSender.Sender, &cList)
		}
	case rainslib.NTCapHashNotKnown:
		if len(section.Data) == 0 {
			sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTCapabilityAnswer, capabilityList)
		} else {
			if capabilityIsHash(section.Data) {
				if caps, ok := capabilities.Get([]byte(section.Data)); ok {
					connCache.AddCapabilityList(msgSender.Sender, caps)
					sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTCapabilityAnswer, capabilityList)
				} else {
					sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTCapHashNotKnown, capabilityList)
				}
			} else {
				cList := []rainslib.Capability{}
				for _, c := range strings.Split(section.Data, " ") {
					cList = append(cList, rainslib.Capability(c))
				}
				connCache.AddCapabilityList(msgSender.Sender, &cList)
				sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTCapabilityAnswer, capabilityList)
			}
		}
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

//capabilityIsHash returns true if capabilities are represented as a hash.
func capabilityIsHash(capabilities string) bool {
	return !strings.HasPrefix(capabilities, "urn:")
}
