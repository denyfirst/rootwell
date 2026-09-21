package certinspect

import (
	"math"
	"time"
)

// TimeWindowStatus describes only the relationship between an evaluation time
// and the certificate's encoded validity interval. It is not a trust verdict.
type TimeWindowStatus string

const (
	TimeWindowWithin       TimeWindowStatus = "within-validity-window"
	TimeWindowExpired      TimeWindowStatus = "expired"
	TimeWindowNotYetValid  TimeWindowStatus = "not-yet-valid"
	TimeWindowInvalidRange TimeWindowStatus = "invalid-range"
)

// TimeWindow is a point-in-time evaluation of a certificate's NotBefore and
// NotAfter fields. Exactly one relative-seconds field is set for a valid range.
type TimeWindow struct {
	Status             TimeWindowStatus
	EvaluatedAt        time.Time
	SecondsUntilStart  *int64
	SecondsUntilExpiry *int64
	SecondsSinceExpiry *int64
}

// EvaluateTimeWindow compares now with an inclusive validity interval. It does
// not verify signatures, trust, hostname, usage, chain, or revocation state.
func EvaluateTimeWindow(notBefore, notAfter, now time.Time) TimeWindow {
	notBefore = notBefore.UTC()
	notAfter = notAfter.UTC()
	now = now.UTC()
	result := TimeWindow{EvaluatedAt: now}

	if notAfter.Before(notBefore) {
		result.Status = TimeWindowInvalidRange
		return result
	}
	if now.Before(notBefore) {
		seconds := secondsBetween(now, notBefore)
		result.Status = TimeWindowNotYetValid
		result.SecondsUntilStart = &seconds
		return result
	}
	if now.After(notAfter) {
		seconds := secondsBetween(notAfter, now)
		result.Status = TimeWindowExpired
		result.SecondsSinceExpiry = &seconds
		return result
	}

	seconds := secondsBetween(now, notAfter)
	result.Status = TimeWindowWithin
	result.SecondsUntilExpiry = &seconds
	return result
}

func secondsBetween(earlier, later time.Time) int64 {
	earlierUnix := earlier.Unix()
	laterUnix := later.Unix()
	if laterUnix < earlierUnix {
		return 0
	}
	if earlierUnix < 0 && laterUnix > math.MaxInt64+earlierUnix {
		return math.MaxInt64
	}
	return laterUnix - earlierUnix
}
