package failoverbudget

import "time"

const (
	// ActiveAvailabilityConfirmations is the fixed routed-DNS confirmation
	// streak. Bulk QoE availability policy is intentionally independent.
	ActiveAvailabilityConfirmations = 2
	// ActivePlanning bounds one route-cover computation slice.
	ActivePlanning = 450 * time.Millisecond
	// ActiveTargetPlanning also covers snapshot preparation and admission to the
	// retained route-cover planner. The end-to-end envelope intentionally
	// favors non-overlapping observations and steady client traffic over the
	// earlier sub-second polling pressure.
	ActiveTargetPlanning = time.Second
	EndToEnd             = 8 * time.Second
)
