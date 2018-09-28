package rainsd

import (
	"strings"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//notify handles incoming notification messages
func notify(msgSender msgSectionSender, caches *Caches, serverConnInfo connection.Info, capabilityList string) {
	notifLog := log.New("notificationMsgSection", msgSender.Section)
	sec := msgSender.Section.(*section.Notification)
	switch sec.Type {
	case section.NTHeartbeat:
	case section.NTCapHashNotKnown:
		if len(sec.Data) == 0 {
			caps, _ := caches.ConnCache.GetCapabilityList(serverConnInfo)
			sendCapability(msgSender.Sender, caps)
		} else {
			if capabilityIsHash(sec.Data) {
				if caps, ok := caches.Capabilities.Get([]byte(sec.Data)); ok {
					caches.ConnCache.AddCapabilityList(msgSender.Sender, caps)
					ownCaps, _ := caches.ConnCache.GetCapabilityList(serverConnInfo)
					sendCapability(msgSender.Sender, ownCaps)
				} else {
					sendNotificationMsg(msgSender.Token, msgSender.Sender, section.NTCapHashNotKnown, capabilityList)
				}
			} else {
				cList := []message.Capability{}
				for _, c := range strings.Split(sec.Data, " ") {
					cList = append(cList, message.Capability(c))
				}
				caches.ConnCache.AddCapabilityList(msgSender.Sender, cList)
				ownCaps, _ := caches.ConnCache.GetCapabilityList(serverConnInfo)
				sendCapability(msgSender.Sender, ownCaps)
			}
		}
	case section.NTBadMessage:
		notifLog.Error("Sent msg was malformed")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*section.Notification), true, caches)
	case section.NTRcvInconsistentMsg:
		notifLog.Error("Sent msg was inconsistent")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*section.Notification), true, caches)
	case section.NTMsgTooLarge:
		notifLog.Error("Sent msg was too large")
		//TODO CFE resend message in smaller chunks
	case section.NTNoAssertionsExist:
		notifLog.Info("Bad request, only clients receive this notification type")
		sendNotificationMsg(msgSender.Token, msgSender.Sender, section.NTBadMessage, "")
	case section.NTUnspecServerErr:
		notifLog.Error("Unspecified error of other server")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*section.Notification), false, caches)
	case section.NTServerNotCapable:
		notifLog.Error("Other server was not capable")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*section.Notification), false, caches)
	case section.NTNoAssertionAvail:
		notifLog.Info("No assertion was available")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*section.Notification), false, caches)
	default:
		notifLog.Warn("No matching notification type")
		sendNotificationMsg(msgSender.Token, msgSender.Sender, section.NTBadMessage, "No matching notification type")
	}
}

//capabilityIsHash returns true if capabilities are represented as a hash.
func capabilityIsHash(capabilities string) bool {
	return !strings.HasPrefix(capabilities, "urn:")
}

//dropPendingSectionsAndQueries removes all entries from the pending caches matching token and
//forwards the received notification or unspecServerErr depending on serverError flag
func dropPendingSectionsAndQueries(token token.Token, notification *section.Notification,
	serverError bool, caches *Caches) {
	for _, ss := range caches.PendingKeys.GetAndRemoveByToken(token) {
		if serverError {
			sendNotificationMsg(ss.Token, ss.Sender, section.NTUnspecServerErr, "")
		} else {
			sendNotificationMsg(ss.Token, ss.Sender, notification.Type, notification.Data)
		}
	}
	sectionSenders, _ := caches.PendingQueries.GetAndRemoveByToken(token, 0)
	for _, ss := range sectionSenders {
		if serverError {
			sendNotificationMsg(ss.Token, ss.Sender, section.NTUnspecServerErr, "")
		} else {
			sendNotificationMsg(ss.Token, ss.Sender, notification.Type, notification.Data)
		}
	}
}
