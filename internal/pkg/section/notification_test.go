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

func CheckNotification(n1, n2 *Notification, t *testing.T) {
	if n1.Type != n2.Type {
		t.Error("Notification Type mismatch")
	}
	if n1.Token != n2.Token {
		t.Error("Notification Token mismatch")
	}
	if n1.Data != n2.Data {
		t.Error("Notification Data mismatch")
	}
}
