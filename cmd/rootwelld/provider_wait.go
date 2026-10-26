package main

import (
	"errors"
	"net/http"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func providerWaitError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, inventorystore.ErrTimingBlocked) {
		http.Error(w, "Provider access is paused for reviewed maintenance. Read saved renewal status; do not reset or restore an old backup to retry.", http.StatusConflict)
		return true
	}
	if errors.Is(err, inventorystore.ErrTimingWait) {
		http.Error(w, "The provider asked Rootwell to wait. Read saved renewal status before another provider request.", http.StatusTooManyRequests)
		return true
	}
	return false
}
