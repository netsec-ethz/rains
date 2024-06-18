package rains

import (
	"github.com/netsec-ethz/rains/internal/pkg/query"
)

// Option enables a client or server to specify performance/privacy tradeoffs
type Option int

//go:generate stringer -type=Option
const (
	QOMinE2ELatency Option = iota + 1
	QOMinLastHopAnswerSize
	QOMinInfoLeakage
	QOCachedAnswersOnly
	QOExpiredAssertionsOk
	QOTokenTracing
	QONoVerificationDelegation
	QONoProactiveCaching
	QOMaxFreshness
)

// AllOptions returns all query options
func AllOptions() []Option {
	return []Option{QOMinE2ELatency, QOMinLastHopAnswerSize,
		QOMinInfoLeakage, QOCachedAnswersOnly,
		QOExpiredAssertionsOk, QOTokenTracing,
		QONoVerificationDelegation,
		QONoProactiveCaching, QOMaxFreshness}
}

func convertOpts(opts []Option) []query.Option {
	var qOpts []query.Option
	for _, o := range opts {
		qOpts = append(qOpts, query.Option(o))
	}
	return qOpts
}
