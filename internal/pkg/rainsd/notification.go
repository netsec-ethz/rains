package rainsd

import (
	"strings"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

//notify handles incoming notification messages
func (s *Server) notify(msgSender util.MsgSectionSender) {
	notifLog := log.New("notificationMsgSection", msgSender.Sections[0])
	sec := msgSender.Sections[0].(*section.Notification)
	switch sec.Type {
	case section.NTHeartbeat:
	case section.NTCapHashNotKnown:
		if len(sec.Data) == 0 {
			caps, _ := s.caches.ConnCache.GetCapabilityList(s.config.ServerAddress)
			sendCapability(msgSender.Sender, caps, s)
		} else {
			if capabilityIsHash(sec.Data) {
				if caps, ok := s.caches.Capabilities.Get([]byte(sec.Data)); ok {
					s.caches.ConnCache.AddCapabilityList(msgSender.Sender, caps)
					ownCaps, _ := s.caches.ConnCache.GetCapabilityList(s.config.ServerAddress)
					sendCapability(msgSender.Sender, ownCaps, s)
				} else {
					sendNotificationMsg(msgSender.Token, msgSender.Sender, section.NTCapHashNotKnown, "", s)
				}
			} else {
				cList := []message.Capability{}
				for _, c := range strings.Split(sec.Data, " ") {
					cList = append(cList, message.Capability(c))
				}
				s.caches.ConnCache.AddCapabilityList(msgSender.Sender, cList)
				ownCaps, _ := s.caches.ConnCache.GetCapabilityList(s.config.ServerAddress)
				sendCapability(msgSender.Sender, ownCaps, s)
			}
		}
	case section.NTBadMessage:
		notifLog.Error("Sent msg was malformed")
		dropPendingSectionsAndQueries(msgSender.Token, sec, true, s)
	case section.NTRcvInconsistentMsg:
		notifLog.Error("Sent msg was inconsistent")
		dropPendingSectionsAndQueries(msgSender.Token, sec, true, s)
	case section.NTMsgTooLarge:
		notifLog.Error("Sent msg was too large")
		//TODO CFE resend message in smaller chunks
	case section.NTNoAssertionsExist:
		notifLog.Info("Bad request, only clients receive this notification type")
		sendNotificationMsg(msgSender.Token, msgSender.Sender, section.NTBadMessage, "", s)
	case section.NTUnspecServerErr:
		notifLog.Error("Unspecified error of other server")
		dropPendingSectionsAndQueries(msgSender.Token, sec, false, s)
	case section.NTServerNotCapable:
		notifLog.Error("Other server was not capable")
		dropPendingSectionsAndQueries(msgSender.Token, sec, false, s)
	case section.NTNoAssertionAvail:
		notifLog.Info("No assertion was available")
		dropPendingSectionsAndQueries(msgSender.Token, sec, false, s)
	default:
		notifLog.Warn("No matching notification type")
		sendNotificationMsg(msgSender.Token, msgSender.Sender, section.NTBadMessage, "No matching notification type", s)
	}
}

//capabilityIsHash returns true if capabilities are represented as a hash.
func capabilityIsHash(capabilities string) bool {
	return !strings.HasPrefix(capabilities, "urn:")
}

//dropPendingSectionsAndQueries removes all entries from the pending caches matching token and
//forwards the received notification or unspecServerErr depending on serverError flag
func dropPendingSectionsAndQueries(token token.Token, notification *section.Notification,
	serverError bool, s *Server) {
	if ss, ok := s.caches.PendingKeys.GetAndRemove(token); ok {
		if serverError {
			sendNotificationMsg(ss.Token, ss.Sender, section.NTUnspecServerErr, "", s)
		} else {
			sendNotificationMsg(ss.Token, ss.Sender, notification.Type, notification.Data, s)
		}
	}
	sectionSenders := s.caches.PendingQueries.GetAndRemove(token)
	for _, ss := range sectionSenders {
		if serverError {
			sendNotificationMsg(ss.Token, ss.Sender, section.NTUnspecServerErr, "", s)
		} else {
			sendNotificationMsg(ss.Token, ss.Sender, notification.Type, notification.Data, s)
		}
	}
}
