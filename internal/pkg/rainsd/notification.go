package rainsd

import (
	"strings"

	"github.com/netsec-ethz/rains/internal/pkg/token"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
)

//notify handles incoming notification messages
func notify(msgSender msgSectionSender) {
	notifLog := log.New("notificationMsgSection", msgSender.Section)
	section := msgSender.Section.(*sections.Notification)
	switch section.Type {
	case sections.NTHeartbeat:
	case sections.NTCapHashNotKnown:
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
					sendNotificationMsg(msgSender.Token, msgSender.Sender, sections.NTCapHashNotKnown, capabilityList)
				}
			} else {
				cList := []message.Capability{}
				for _, c := range strings.Split(section.Data, " ") {
					cList = append(cList, message.Capability(c))
				}
				connCache.AddCapabilityList(msgSender.Sender, cList)
				ownCaps, _ := connCache.GetCapabilityList(serverConnInfo)
				sendCapability(msgSender.Sender, ownCaps)
			}
		}
	case sections.NTBadMessage:
		notifLog.Error("Sent msg was malformed")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*sections.Notification), true)
	case sections.NTRcvInconsistentMsg:
		notifLog.Error("Sent msg was inconsistent")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*sections.Notification), true)
	case sections.NTMsgTooLarge:
		notifLog.Error("Sent msg was too large")
		//TODO CFE resend message in smaller chunks
	case sections.NTNoAssertionsExist:
		notifLog.Info("Bad request, only clients receive this notification type")
		sendNotificationMsg(msgSender.Token, msgSender.Sender, sections.NTBadMessage, "")
	case sections.NTUnspecServerErr:
		notifLog.Error("Unspecified error of other server")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*sections.Notification), false)
	case sections.NTServerNotCapable:
		notifLog.Error("Other server was not capable")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*sections.Notification), false)
	case sections.NTNoAssertionAvail:
		notifLog.Info("No assertion was available")
		dropPendingSectionsAndQueries(msgSender.Token,
			msgSender.Section.(*sections.Notification), false)
	default:
		notifLog.Warn("No matching notification type")
		sendNotificationMsg(msgSender.Token, msgSender.Sender, sections.NTBadMessage, "No matching notification type")
	}
}

//capabilityIsHash returns true if capabilities are represented as a hash.
func capabilityIsHash(capabilities string) bool {
	return !strings.HasPrefix(capabilities, "urn:")
}

//dropPendingSectionsAndQueries removes all entries from the pending caches matching token and
//forwards the received notification or unspecServerErr depending on serverError flag
func dropPendingSectionsAndQueries(token token.Token, notification *sections.Notification,
	serverError bool) {
	for _, ss := range pendingKeys.GetAndRemoveByToken(token) {
		if serverError {
			sendNotificationMsg(ss.Token, ss.Sender, sections.NTUnspecServerErr, "")
		} else {
			sendNotificationMsg(ss.Token, ss.Sender, notification.Type, notification.Data)
		}
	}
	sectionSenders, _ := pendingQueries.GetAndRemoveByToken(token, 0)
	for _, ss := range sectionSenders {
		if serverError {
			sendNotificationMsg(ss.Token, ss.Sender, sections.NTUnspecServerErr, "")
		} else {
			sendNotificationMsg(ss.Token, ss.Sender, notification.Type, notification.Data)
		}
	}
}
