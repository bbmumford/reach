// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import "crypto/rand"

// randFill populates b with cryptographically random bytes. Best-effort — on
// error the buffer is left whatever the caller initialized it to.
func randFill(b []byte) {
	_, _ = rand.Read(b)
}
