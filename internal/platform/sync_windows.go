package platform

import "os"

// SyncDirectory is a no-op: Windows does not support fsync on directory handles.
// File contents are still synced before rename; Linux durability is unchanged.
func SyncDirectory(*os.File) error { return nil }
