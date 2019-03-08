package rains

import (
	"fmt"

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

// ParseOptions returns the query option(s) specified in opt
func ParseOptions(opt string) ([]Option, error) {
	switch opt {
	case "minEE":
		return []Option{QOMinE2ELatency}, nil
	case "minAS":
		return []Option{QOMinLastHopAnswerSize}, nil
	case "minIL":
		return []Option{QOMinInfoLeakage}, nil
	case "noIL":
		return []Option{QOCachedAnswersOnly}, nil
	case "exp":
		return []Option{QOExpiredAssertionsOk}, nil
	case "tracing":
		return []Option{QOTokenTracing}, nil
	case "noVD":
		return []Option{QONoVerificationDelegation}, nil
	case "noCaching":
		return []Option{QONoProactiveCaching}, nil
	case "maxAF":
		return []Option{QOMaxFreshness}, nil
	case "all":
		return AllOptions(), nil
	}
	return []Option{Option(-1)}, fmt.Errorf("%s is not a query option", opt)
}

// CLIString returns the CLI type string corresponding to the query option specified in opt
func (opt Option) CLIString() string {
	switch opt {
	case QOMinE2ELatency:
		return "minEE"
	case QOMinLastHopAnswerSize:
		return "minAS"
	case QOMinInfoLeakage:
		return "minIL"
	case QOCachedAnswersOnly:
		return "noIL"
	case QOExpiredAssertionsOk:
		return "exp"
	case QOTokenTracing:
		return "tracing"
	case QONoVerificationDelegation:
		return "noVD"
	case QONoProactiveCaching:
		return "noCaching"
	case QOMaxFreshness:
		return "maxAF"
	default:
		return opt.String()
	}
}

//AllOptions returns all query options
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
