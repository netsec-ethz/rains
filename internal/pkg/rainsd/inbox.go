package rainsd

import (
	"fmt"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/cache"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/siglib"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

type InputQueues struct {
	//incoming messages are buffered in one of these channels until they get processed by a worker
	//go routine the prioChannel only contains incoming sections in response to a delegation query
	//issued by this server.
	Prio   chan util.MsgSectionSender
	Normal chan util.MsgSectionSender
	Notify chan util.MsgSectionSender

	//These channels limit the number of go routines working on the different queues to avoid memory
	//exhaustion.
	PrioW   chan struct{}
	NormalW chan struct{}
	NotifyW chan struct{}
}

//deliver pushes all incoming messages to the prio or normal channel.
//A message is added to the priority channel if it is the response to a non-expired delegation query
func deliver(msg *message.Message, sender connection.Info, prioChannel chan util.MsgSectionSender,
	normalChannel chan util.MsgSectionSender, notificationChannel chan util.MsgSectionSender,
	pendingKeys cache.PendingKey) {
	if !siglib.CheckMessageSignatures(msg, keys.PublicKey{}) {
		//Infra keys are not yet supported
	}

	processCapability(msg.Capabilities, sender, msg.Token)

	//handle notification separately. Assertions and Queries are processed together respectively.
	queries := []section.Section{}
	sections := []section.Section{}
	for _, m := range msg.Content {
		switch m := m.(type) {
		case *section.Assertion, *section.Shard, *section.Pshard, *section.Zone:
			if !isZoneBlacklisted(m.(section.WithSig).GetSubjectZone()) {
				sections = append(sections, m)
				trace(msg.Token, fmt.Sprintf("added message section to queue: %v", m))
			}
		case *query.Name:
			log.Debug(fmt.Sprintf("add %T to normal queue", m))
			queries = append(queries, m)
			trace(msg.Token, fmt.Sprintf("sent query section %v to normal channel", m))
		case *section.Notification:
			log.Debug("Add notification to notification queue", "token", msg.Token)
			notificationChannel <- util.MsgSectionSender{
				Sender:   sender,
				Sections: []section.Section{m},
				Token:    msg.Token,
			}
			trace(msg.Token, fmt.Sprintf("sent notification section %v to notification channel", m))
		default:
			log.Warn(fmt.Sprintf("unsupported message section type %T", m))
			trace(msg.Token, fmt.Sprintf("unsupported message section type: %T", m))
			return
		}
	}
	if len(queries) > 0 {
		normalChannel <- util.MsgSectionSender{Sender: sender, Sections: queries, Token: msg.Token}
	}
	if len(sections) > 0 {
		mss := util.MsgSectionSender{Sender: sender, Sections: sections, Token: msg.Token}
		if pendingKeys.ContainsToken(msg.Token) {
			log.Debug("add section with signature to priority queue", "token", msg.Token)
			prioChannel <- mss
		} else {
			log.Debug("add section with signature to normal queue", "token", msg.Token)
			normalChannel <- mss
		}
	}
}

//processCapability processes capabilities and sends a notification back to the sender if the hash
//is not understood.
func processCapability(caps []message.Capability, sender connection.Info, token token.Token) {
	log.Debug("Processing Capabilities not yet supported")
	/*log.Debug("Process capabilities", "capabilities", caps)
	if len(caps) > 0 {
		isHash := !strings.HasPrefix(string(caps[0]), "urn:")
		if isHash {
			if caps, ok := capabilities.Get([]byte(caps[0])); ok {
				addCapabilityAndRespond(sender, caps)
			} else { //capability hash not understood
				sendNotificationMsg(token, sender, section.NTCapHashNotKnown, capabilityHash)
			}
		} else {
			addCapabilityAndRespond(sender, caps)
		}
	}*/
}

//addCapabilityAndRespond adds caps to the connection cache entry of sender and sends its own
//capabilities back if it has not already received capability information on this connection.
func addCapabilityAndRespond(sender connection.Info, caps []message.Capability) {
	/*if !connCache.AddCapabilityList(sender, caps) {
		sendCapability(sender, []message.Capability{message.Capability(capabilityHash)})
	}*/
}

//isZoneBlacklisted returns true if zone is blacklisted
func isZoneBlacklisted(zone string) bool {
	log.Debug("TODO CFE zone blacklist not yet implemented")
	return false
}

//workBoth works on the prioChannel and on the normalChannel. A worker only fetches a message from
//the normalChannel if the prioChannel is empty. the channel normalWorkers enforces a maximum number
//of go routines working on the prioChannel and normalChannel.
func (s *Server) workBoth() {
	for {
		select {
		case <-s.shutdown:
			//Avoid closing the s.queues.Normal channel before server.Shutdown() has sent a dummy
			//message in case this worker is not waiting on the s.queues.Normal channel
			time.Sleep(time.Second)
			close(s.queues.Normal)
			close(s.queues.NormalW)
			return
		default:
		}
		s.queues.NormalW <- struct{}{}
		select {
		case msg := <-s.queues.Prio:
			go prioWorkerHandler(s, msg, false)
			continue
		default:
			//do nothing
		}
		select {
		case msg := <-s.queues.Normal:
			go normalWorkerHandler(s, msg)
		default:
			<-s.queues.NormalW
		}
	}
}

//normalWorkerHandler handles sections on the normalChannel
func normalWorkerHandler(s *Server, msg util.MsgSectionSender) {
	if msg.Sections != nil {
		s.verify(msg)
	}
	<-s.queues.NormalW
}

//workPrio works on the prioChannel. It waits on the prioChannel and creates a new go routine which handles the section.
//the channel prioWorkers enforces a maximum number of go routines working on the prioChannel.
//The prio channel is necessary to avoid a blocking of the server. e.g. in the following unrealistic scenario
//1) normal queue fills up with non delegation queries which all are missing a public key
//2) The non-delegation queries get processed by the normalWorkers and added to the pendingSignature cache
//3) For each non-delegation query that gets taken off the queue a new non-delegation query or expired
//   delegation query wins against all waiting valid delegation-queries.
//4) Then although the server is working all the time, no section is added to the caches.
func (s *Server) workPrio() {
	for {
		select {
		case <-s.shutdown:
			//Avoid closing the s.queues.Prio channel before server.Shutdown() has sent a dummy
			//message in case this worker is not waiting on the s.queues.Prio channel
			time.Sleep(time.Second)
			close(s.queues.Prio)
			close(s.queues.PrioW)
			return
		default:
		}
		s.queues.PrioW <- struct{}{}
		msg := <-s.queues.Prio
		go prioWorkerHandler(s, msg, true)
	}
}

//prioWorkerHandler handles sections on the prioChannel
func prioWorkerHandler(s *Server, msg util.MsgSectionSender, prioWorker bool) {
	if msg.Sections != nil {
		s.verify(msg)
	}
	if prioWorker {
		<-s.queues.PrioW
	}
}

//workNotification works on the notificationChannel. It waits on the notificationChannel and creates
//a new go routine which handles the notification. the channel notificationWorkers enforces a
//maximum number of go routines working on the notificationChannel
func (s *Server) workNotification() {
	for {
		select {
		case <-s.shutdown:
			//Avoid closing the s.queues.Notify channel before server.Shutdown() has sent a dummy
			//message in case this worker is not waiting on the s.queues.Notify channel
			time.Sleep(time.Second)
			close(s.queues.Notify)
			close(s.queues.NotifyW)
			return
		default:
		}
		s.queues.NotifyW <- struct{}{}
		msg := <-s.queues.Notify
		go handleNotification(s, msg)
	}
}

//handleNotification works on notificationChannel.
func handleNotification(s *Server, msg util.MsgSectionSender) {
	if msg.Sections != nil {
		s.notify(msg)
	}
	<-s.queues.NormalW
}
