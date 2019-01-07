package section

import (
	"sort"
	"testing"
)

func TestNotificationCompareTo(t *testing.T) {
	ns := sortedNotifications(5)
	var shuffled []Section
	for _, n := range ns {
		shuffled = append(shuffled, n)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*Notification).CompareTo(shuffled[j].(*Notification)) < 0
	})
	for i, n := range ns {
		CheckNotification(n, shuffled[i].(*Notification), t)
	}
}
