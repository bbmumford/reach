// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import "time"

// nowForTest returns a stable-ish "now" for test assertions where the exact
// instant is immaterial.
func nowForTest() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}
