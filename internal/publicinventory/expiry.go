package publicinventory

import "time"

// Expiry is a date-only observation, not a trust or deployment verdict.
// DaysLeft rounds a positive remainder up; absent for invalid dates.
type Expiry struct {
	Status   string `json:"status"`
	DaysLeft *int64 `json:"days_left,omitempty"`
}

// ObserveExpiry uses only the supplied server-clock instant and public dates.
// Unix-second subtraction avoids time.Duration saturation on long-lived certs.
// The strict canonical representation is shared by the inventory codec.
func ObserveExpiry(record Record, now time.Time) Expiry {
	start, errStart := time.Parse("2006-01-02T15:04:05Z", record.NotBefore)
	end, errEnd := time.Parse("2006-01-02T15:04:05Z", record.NotAfter)
	if errStart != nil || errEnd != nil || start.Format("2006-01-02T15:04:05Z") != record.NotBefore ||
		end.Format("2006-01-02T15:04:05Z") != record.NotAfter || !start.Before(end) || now.Year() < 0 || now.Year() > 9999 {
		return Expiry{Status: "invalid"}
	}
	seconds := end.Unix() - now.Unix()
	days := seconds / 86400
	if seconds > 0 && seconds%86400 != 0 {
		days++
	}
	result := Expiry{DaysLeft: &days}
	switch {
	case !now.Before(end):
		result.Status = "expired"
	case now.Before(start):
		result.Status = "future"
	case seconds <= 30*86400:
		result.Status = "soon"
	case seconds <= 90*86400:
		result.Status = "medium"
	default:
		result.Status = "later"
	}
	return result
}
