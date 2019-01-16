package section

import (
	"math/rand"
	"sort"
	"testing"
)

func TestNotificationCompareTo(t *testing.T) {
	ns := sortedNotifications(5)
	shuffled := append([]*Notification{}, ns...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].CompareTo(shuffled[j]) < 0
	})
	for i, n := range ns {
		checkNotification(n, shuffled[i], t)
	}
}

func checkNotification(n1, n2 *Notification, t *testing.T) {
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
