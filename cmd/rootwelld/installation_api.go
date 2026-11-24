package main

import (
	"bytes"
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
	_, _, ok := g.freshChange(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	var copy bytes.Buffer
	if _, err := g.vault.Backup(&copy); err != nil {
		http.Error(w, "the backup could not be made", http.StatusServiceUnavailable)
		return
	}
	if copy.Len() > maxPageBackup {
		http.Error(w, "This vault is too large to download here; copy it on the server with Rootwell stopped.", http.StatusInsufficientStorage)
		return
	}
	name := "rootwell-backup-" + g.now().UTC().Format("20060102T150405Z") + ".db"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(copy.Len()))
	_, _ = w.Write(copy.Bytes())
}
