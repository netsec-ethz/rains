package rainsd

import (
	"strings"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainslib"
)

//notify handles incoming notification messages
func notify(msgSender msgSectionSender) {
	notifLog := log.New("notificationMsgSection", msgSender.Section)
	section := msgSender.Section.(*rainslib.NotificationSection)
	switch section.Type {
	case rainslib.NTHeartbeat:
	case rainslib.NTCapHashNotKnown:
		if len(section.Data) == 0 {
			caps, _ := connCache.GetCapabilityList(serverConnInfo)
			sendCapability(msgSender.Sender, caps)
		} else {
			if capabilityIsHash(section.Data) {
				if caps, ok := capabilities.Get([]byte(section.Data)); ok {
					connCache.AddCapabilityList(msgSender.Sender, caps)
					ownCaps, _ := connCache.GetCapabilityList(serverConnInfo)
					sendCapability(msgSender.Sender, ownCaps)
				} else {
					sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTCapHashNotKnown, capabilityList)
				}
			} else {
				cList := []rainslib.Capability{}
				for _, c := range strings.Split(section.Data, " ") {
					cList = append(cList, rainslib.Capability(c))
				}
				connCache.AddCapabilityList(msgSender.Sender, cList)
				ownCaps, _ := connCache.GetCapabilityList(serverConnInfo)
				sendCapability(msgSender.Sender, ownCaps)
			}
		}
	case rainslib.NTBadMessage:
		notifLog.Error("Sent msg was malformed")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*rainslib.NotificationSection), true)
	case rainslib.NTRcvInconsistentMsg:
		notifLog.Error("Sent msg was inconsistent")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*rainslib.NotificationSection), true)
	case rainslib.NTMsgTooLarge:
		notifLog.Error("Sent msg was too large")
		//TODO CFE resend message in smaller chunks
	case rainslib.NTNoAssertionsExist:
		notifLog.Info("Bad request, only clients receive this notification type")
		sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTBadMessage, "")
	case rainslib.NTUnspecServerErr:
		notifLog.Error("Unspecified error of other server")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*rainslib.NotificationSection), false)
	case rainslib.NTServerNotCapable:
		notifLog.Error("Other server was not capable")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*rainslib.NotificationSection), false)
	case rainslib.NTNoAssertionAvail:
		notifLog.Info("No assertion was available")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*rainslib.NotificationSection), false)
	default:
		notifLog.Warn("No matching notification type")
		sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTBadMessage, "No matching notification type")
	}
}

//capabilityIsHash returns true if capabilities are represented as a hash.
func capabilityIsHash(capabilities string) bool {
	return !strings.HasPrefix(capabilities, "urn:")
}

//dropPendingSectionsAndQueries removes all entries from the pending caches matching token and
//forwards the received notification or unspecServerErr depending on serverError flag
func dropPendingSectionsAndQueries(token rainslib.Token, notification *rainslib.NotificationSection,
	serverError bool) {
	for _, ss := range pendingKeys.GetAndRemoveByToken(token) {
		if serverError {
			sendNotificationMsg(ss.Token, ss.Sender, rainslib.NTUnspecServerErr, "")
		} else {
			sendNotificationMsg(ss.Token, ss.Sender, notification.Type, notification.Data)
		}
	}
	sectionSenders, _ := pendingQueries.GetAndRemoveByToken(token, 0)
	for _, ss := range sectionSenders {
		if serverError {
			sendNotificationMsg(ss.Token, ss.Sender, rainslib.NTUnspecServerErr, "")
		} else {
			sendNotificationMsg(ss.Token, ss.Sender, notification.Type, notification.Data)
		}
	}
}
