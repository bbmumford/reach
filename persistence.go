// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// lastGood is the JSON shape persisted to Config.PersistPath.
// Used to seed the publisher's in-memory state on cold start so a restart
// doesn't re-publish an identical record purely because the old digest was
// lost in memory.
type lastGood struct {
	Digest     string      `json:"digest"`
	Addresses  []Address   `json:"addresses"`
	Record     ReachRecord `json:"record"`
	Epoch      uint64      `json:"epoch"`
	WrittenAt  string      `json:"written_at"`
}

// saveLastGood writes the most recent published record to disk.
// Best-effort — errors are logged by the caller but never block publishing.
func (p *Publisher) saveLastGood(rec ReachRecord) error {
	if p.cfg.PersistPath == "" {
		return nil
	}
	payload := lastGood{
		Digest:    p.lastDigest,
		Addresses: p.lastAddresses,
		Record:    rec,
		Epoch:     p.cfg.Epoch,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	// Ensure parent dir exists.
	if err := os.MkdirAll(filepath.Dir(p.cfg.PersistPath), 0o700); err != nil {
		return err
	}
	// Atomic write via temp + rename.
	tmp := p.cfg.PersistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.cfg.PersistPath)
}

// loadLastGood restores the in-memory digest from disk on cold start.
// Non-fatal — a missing file just means "no prior state".
//
// Seeds the Epoch: if the persisted Epoch is at-or-after the newly-generated
// one, we bump the in-memory Epoch to prev+1 so strict monotonicity holds
// across restarts even when the wall clock rolls backward between process
// lifetimes (plan §5.31).
func (p *Publisher) loadLastGood() error {
	if p.cfg.PersistPath == "" {
		return nil
	}
	data, err := os.ReadFile(p.cfg.PersistPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var payload lastGood
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastDigest = payload.Digest
	p.lastAddresses = payload.Addresses
	if payload.Epoch >= p.cfg.Epoch {
		p.cfg.Epoch = payload.Epoch + 1
	}
	return nil
}
