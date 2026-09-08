package tournament

import (
	"sort"
	"time"
)

type Candidate struct {
	Fingerprint       string
	Status            Status
	FullSuccessStreak int
	ConservativeScore float64
	InWorkingPool     bool
	Assigned          bool
	Draining          bool
	Stale             bool
	NearBoundary      bool
	BannedUntil       time.Time
	WindowStartedAt   time.Time
	LastFastProbeAt   time.Time
	LastFullProbeAt   time.Time
}

type SelectionPolicy struct {
	PoolSize       int
	PromotionRatio float64
	Now            time.Time
}

type Selection struct {
	Active   []string
	Draining []string
}

func SelectWorkingPool(candidates []Candidate, policy SelectionPolicy) Selection {
	if policy.PoolSize <= 0 {
		return Selection{}
	}
	current := make([]Candidate, 0, policy.PoolSize)
	challengers := make([]Candidate, 0, len(candidates))
	draining := make(map[string]bool)
	for _, candidate := range candidates {
		eligible := candidate.Status == StatusQualified &&
			candidate.FullSuccessStreak >= 2 &&
			(candidate.BannedUntil.IsZero() || !policy.Now.Before(candidate.BannedUntil))
		if candidate.InWorkingPool && eligible {
			current = append(current, candidate)
			continue
		}
		if candidate.InWorkingPool && candidate.Assigned {
			draining[candidate.Fingerprint] = true
		}
		if eligible {
			challengers = append(challengers, candidate)
		}
	}
	sortByScoreDescending(current)
	sortByScoreDescending(challengers)
	if len(current) > policy.PoolSize {
		for _, candidate := range current[policy.PoolSize:] {
			if candidate.Assigned {
				draining[candidate.Fingerprint] = true
			}
		}
		current = current[:policy.PoolSize]
	}
	for len(current) < policy.PoolSize && len(challengers) > 0 {
		current = append(current, challengers[0])
		challengers = challengers[1:]
		sortByScoreDescending(current)
	}
	for _, challenger := range challengers {
		if len(current) == 0 {
			break
		}
		worstIndex := len(current) - 1
		worst := current[worstIndex]
		required := worst.ConservativeScore * (1 + policy.PromotionRatio)
		if challenger.ConservativeScore < required {
			continue
		}
		if worst.Assigned {
			draining[worst.Fingerprint] = true
		}
		current[worstIndex] = challenger
		sortByScoreDescending(current)
	}

	result := Selection{Active: make([]string, 0, len(current))}
	for _, candidate := range current {
		result.Active = append(result.Active, candidate.Fingerprint)
	}
	sort.Strings(result.Active)
	for fingerprint := range draining {
		result.Draining = append(result.Draining, fingerprint)
	}
	sort.Strings(result.Draining)
	return result
}

func sortByScoreDescending(candidates []Candidate) {
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].ConservativeScore == candidates[right].ConservativeScore {
			return candidates[left].Fingerprint < candidates[right].Fingerprint
		}
		return candidates[left].ConservativeScore > candidates[right].ConservativeScore
	})
}
