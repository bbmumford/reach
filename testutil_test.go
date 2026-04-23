// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import "time"

// nowForTest returns a stable-ish "now" for test assertions where the exact
// instant is immaterial.
func nowForTest() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}
