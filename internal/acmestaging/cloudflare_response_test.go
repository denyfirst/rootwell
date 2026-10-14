package acmestaging

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCloudflareCleanupAbsenceRequiresCompleteMatchingListAndNoDelete(t *testing.T) {
	scope := cfScope()
	record := cfFixtureRecord(scope)
	deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("absence reconciliation deleted a record")
		}
		if strings.HasSuffix(r.URL.Path, "/"+record.ID) {
			w.WriteHeader(404)
		} else if strings.HasSuffix(r.URL.Path, "/dns_records") {
			cfList(w, []cfRecord{})
		} else {
			cfZoneReply(w, scope)
		}
	})
	result, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "deleting", ID: record.ID}, true, true, nil)
	if err != nil || result != (dnsRecordState{State: "deleted"}) {
		t.Fatal("confirmed filtered absence refused", err)
	}
	noIO := dependencies{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("borrowed cleanup contacted provider")
		return nil, errDNS
	}}
	if _, err := cloudflareRecord(context.Background(), func() bool { return true }, noIO, cfTestToken, scope, dnsRecordState{State: "borrowed"}, true, true, nil); err == nil {
		t.Fatal("borrowed record acquired cleanup capability")
	}
	if result, err := cloudflareRecord(context.Background(), func() bool { return true }, noIO, cfTestToken, scope, dnsRecordState{State: "deleting", ID: record.ID}, true, false, func(dnsRecordState) error { t.Error("uncertain deletion renewed intent"); return nil }); err == nil || result != (dnsRecordState{}) {
		t.Fatal("uncertain deletion acquired replay authority")
	}
}

func TestCloudflareRevocationAfterIntentNeverTransmitsMutation(t *testing.T) {
	scope := cfScope()
	var allowed atomic.Bool
	allowed.Store(true)
	var calls atomic.Int32
	deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" {
			t.Error("revoked intent transmitted a DNS mutation")
		}
		if strings.HasSuffix(r.URL.Path, "/dns_records") {
			cfList(w, []cfRecord{})
		} else {
			cfZoneReply(w, scope)
		}
	})
	result, err := cloudflareRecord(context.Background(), allowed.Load, deps, cfTestToken, scope, dnsRecordState{State: "new"}, false, false, func(dnsRecordState) error { allowed.Store(false); return nil })
	if err == nil || result != (dnsRecordState{}) || calls.Load() != 2 {
		t.Fatal("revoked publication/mutation boundary failed")
	}
}

func TestCloudflareRecordAliasesAndIncompletePaginationRefuseWithoutWrite(t *testing.T) {
	scope := cfScope()
	record := cfFixtureRecord(scope)
	goodRecord, _ := json.Marshal(record)
	list := `{"success":true,"errors":[],"result":[` + string(goodRecord) + `],"result_info":{"page":1,"total_pages":1,"count":1,"total_count":1}}`
	for _, body := range []string{
		strings.Replace(list, `"comment":`, `"Comment":`, 1),
		strings.Replace(list, `"proxied":false`, `"proxied":null`, 1),
		strings.Replace(list, `"proxied":false`, `"unrelated":false`, 1),
		strings.Replace(list, `"count":1`, `"count":null`, 1),
		strings.Replace(list, `"total_count":1`, `"unknown_count":1`, 1),
		strings.Replace(list, `"total_pages":1`, `"total_pages":2`, 1),
		strings.Replace(list, `"total_count":1`, `"total_count":101`, 1),
		strings.Replace(list, `"count":1`, `"count":0`, 1),
	} {
		deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Error("malformed list led to write")
			}
			if strings.HasSuffix(r.URL.Path, "/dns_records") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			} else {
				cfZoneReply(w, scope)
			}
		})
		if result, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "creating"}, false, true, nil); err == nil || result != (dnsRecordState{}) {
			t.Fatal("malformed list fabricated ownership")
		}
	}
}
