// Package renewalpolicy supplies bounded offline ARI parsing and time selection.
// It cannot fetch, sign, save, unlock, issue or grant authority to renew.
package renewalpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxInformationBytes = 8 << 10

var ErrInvalid = errors.New("renewal policy unavailable")

// time.Parse also accepts comma fractions and some out-of-range UTC offsets;
// constrain the wire grammar before using its calendar/instant validation.
var timestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

type Window struct{ Start, End time.Time }
type Information struct {
	Window                Window
	CheckedAt, CheckAfter time.Time
}

func validTime(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 2020 && t.UTC().Year() <= 2100
}
func validWindow(w Window) bool {
	return validTime(w.Start) && validTime(w.End) && w.End.After(w.Start)
}

// ParseInformation accepts untrusted public bytes, NOT an authenticated CA
// observation. A future scoped pinned connector must establish their source.
// No explanation/extension URL or metadata is retained or followed.
func ParseInformation(body []byte, retryAfter []string, checked time.Time) (Information, error) {
	bad := func() (Information, error) { return Information{}, ErrInvalid }
	if len(body) == 0 || len(body) > MaxInformationBytes || !utf8.Valid(body) || !validTime(checked) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	budget := 256
	if !uniqueValue(d, 0, &budget) {
		return bad()
	}
	if _, err := d.Token(); err != io.EOF {
		return bad()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return bad()
	}
	for name := range fields {
		if name != "suggestedWindow" && strings.EqualFold(name, "suggestedWindow") || name != "explanationURL" && strings.EqualFold(name, "explanationURL") {
			return bad()
		}
	}
	var window map[string]json.RawMessage
	if json.Unmarshal(fields["suggestedWindow"], &window) != nil || len(window) != 2 {
		return bad()
	}
	parse := func(raw json.RawMessage) (time.Time, bool) {
		var s string
		if json.Unmarshal(raw, &s) != nil || len(s) > 40 || !timestamp.MatchString(s) {
			return time.Time{}, false
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		return t.UTC(), err == nil && validTime(t)
	}
	start, ok := parse(window["start"])
	end, valid := parse(window["end"])
	if !ok || !valid || !end.After(start) {
		return bad()
	}
	if raw, ok := fields["explanationURL"]; ok {
		var ignored *string
		if json.Unmarshal(raw, &ignored) != nil || ignored == nil || len(*ignored) > 2048 {
			return bad()
		}
	}
	next, err := NextCheck(retryAfter, checked)
	if err != nil {
		return bad()
	}
	return Information{Window: Window{start, end}, CheckedAt: checked.UTC(), CheckAfter: next}, nil
}

// NextCheck follows ARI's checking policy, not DNS mutation Retry-After policy:
// valid intervals clamp to [1 minute,1 day]. Invalid/missing hints need the
// separate six-hour error policy, not an immediate retry or a trusted window.
func NextCheck(values []string, now time.Time) (time.Time, error) {
	if !validTime(now) || len(values) != 1 || len(values[0]) < 1 || len(values[0]) > 64 {
		return time.Time{}, ErrInvalid
	}
	value := values[0]
	digits := true
	for _, c := range value {
		if c < '0' || c > '9' {
			digits = false
			break
		}
	}
	var delay time.Duration
	if digits {
		seconds, err := strconv.ParseUint(value, 10, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return time.Time{}, ErrInvalid
		}
		if err != nil || seconds >= 86400 {
			delay = 24 * time.Hour
		} else {
			delay = time.Duration(seconds) * time.Second
		}
	} else {
		stamp, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", value)
		if err != nil || stamp.Format("Mon, 02 Jan 2006 15:04:05 GMT") != value || !validTime(stamp) {
			return time.Time{}, ErrInvalid
		}
		delay = stamp.Sub(now)
	}
	delay = max(time.Minute, min(24*time.Hour, delay))
	next := now.UTC().Add(delay)
	if !validTime(next) {
		return time.Time{}, ErrInvalid
	}
	return next, nil
}

// ErrorCheckAt is an offline delay calculation, not a retry loop. Caller must
// persist failures/wait BEFORE every future read; an error cannot replay writes.
// After five temporary errors the sixth uses the long-term six-hour interval.
func ErrorCheckAt(now time.Time, temporary bool, failures int) (time.Time, error) {
	if !validTime(now) || failures < 1 || failures > 6 {
		return time.Time{}, ErrInvalid
	}
	delay := 6 * time.Hour
	if temporary && failures < 6 {
		delay = time.Minute * time.Duration(1<<(failures-1))
	}
	next := now.UTC().Add(delay)
	if !validTime(next) {
		return time.Time{}, ErrInvalid
	}
	return next, nil
}

func uniqueValue(d *json.Decoder, depth int, budget *int) bool {
	*budget--
	if depth > 8 || *budget < 0 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, container := token.(json.Delim)
	if !container {
		return true
	}
	if delim != '{' && delim != '[' {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			token, err = d.Token()
			name, ok := token.(string)
			if err != nil || !ok || seen[name] {
				return false
			}
			seen[name] = true
		}
		if !uniqueValue(d, depth+1, budget) {
			return false
		}
	}
	end, err := d.Token()
	return err == nil && (delim == '{' && end == json.Delim('}') || delim == '[' && end == json.Delim(']'))
}
