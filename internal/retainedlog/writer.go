package retainedlog

import "time"

// Config defines the storage and retention policy for a Writer.
type Config struct {
	Directory       string
	Service         string
	Retention       time.Duration
	SegmentDuration time.Duration
	CleanupInterval time.Duration
	Now             func() time.Time
	Remove          func(string) error
}
