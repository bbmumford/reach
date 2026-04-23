// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import "crypto/rand"

// randFill populates b with cryptographically random bytes. Best-effort — on
// error the buffer is left whatever the caller initialized it to.
func randFill(b []byte) {
	_, _ = rand.Read(b)
}
