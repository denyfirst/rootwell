package main

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/denyfirst/rootwell/internal/servingstore"
)

// maxPageBackup is the largest backup the page hands out; a bigger vault is
// copied on the server with the service stopped.
const maxPageBackup = 64 << 20

// installationEndpoint tells the Installation page how browsers reach this
// Rootwell and what a backup would hold.
func (g *gate) installationEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	_, _, ok := g.ready(w, r)
	if !ok {
		return
	}
	s, err := servingstore.Load(g.vault)
	if err != nil {
		http.Error(w, "the serving certificate could not be read", http.StatusServiceUnavailable)
		return
	}
	records, _, err := g.certificates.List()
	if err != nil {
		http.Error(w, "the certificate list could not be read", http.StatusServiceUnavailable)
		return
	}
	names := append([]string{}, s.Names.DNS...)
	for _, ip := range s.Names.IPs {
		names = append(names, ip.String())
	}
	writeJSON(w, http.StatusOK, map[string]any{"names": names, "fingerprint": s.Fingerprint(),
		"serving_until": s.Certificate.Leaf.NotAfter.UTC().Format(time.RFC3339), "certificates": len(records)})
}

// backupEndpoint hands out a consistent copy of the whole vault, made while
// Rootwell keeps running. It needs a fresh code: the copy holds every key,
// sealed under the instance key it does not hold.
func (g *gate) backupEndpoint(w http.ResponseWriter, r *http.Request) {
	_, s, ok := g.freshChange(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	// One backup at a time: each holds up to maxPageBackup in memory.
	select {
	case g.backups <- struct{}{}:
		defer func() { <-g.backups }()
	default:
		http.Error(w, "Another backup is being made. Try again in a moment.", http.StatusServiceUnavailable)
		return
	}
	copy := &cappedBuffer{limit: maxPageBackup}
	if _, err := g.vault.Backup(copy); err != nil && !copy.over {
		http.Error(w, "the backup could not be made", http.StatusServiceUnavailable)
		return
	}
	if copy.over {
		http.Error(w, "This vault is too large to download here; copy it on the server with Rootwell stopped.", http.StatusInsufficientStorage)
		return
	}
	// The person may have signed out, or the account changed, while the copy
	// was made: it goes only to the session that asked for it.
	if !g.stillReady(r, s) || r.Context().Err() != nil {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	name := "rootwell-backup-" + g.now().UTC().Format("20060102T150405Z") + ".db"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(copy.Len()))
	_, _ = w.Write(copy.Bytes())
}

// cappedBuffer keeps at most limit bytes and stops the copy past them, so a
// vault too large for the page never sits whole in memory.
type cappedBuffer struct {
	bytes.Buffer
	limit int
	over  bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.limit {
		c.over = true
		return 0, errTooLarge
	}
	return c.Buffer.Write(p)
}

var errTooLarge = errors.New("backup too large for the page")
