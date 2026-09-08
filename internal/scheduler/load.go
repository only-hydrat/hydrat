package scheduler

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"time"
)

func rendezvous(
	key string,
	candidates []Candidate,
	load map[string]int,
	domainLoad map[string]int,
) string {
	if len(candidates) == 0 {
		return ""
	}
	selected := ""
	bestScore := -1.0
	for _, candidate := range candidates {
		candidateLoad := load[candidate.ID]
		cDomainLoad := domainLoad[candidateDomain(candidate)]
		effectiveScore := math.Max(candidate.Score, 0.001) /
			(1.0 + 0.05*float64(candidateLoad) + 0.02*float64(cDomainLoad))

		digest := sha256.Sum256([]byte(key + "\x00" + candidate.ID))
		raw := binary.BigEndian.Uint64(digest[:8])
		uniform := (float64(raw) + 1) / (float64(math.MaxUint64) + 1)
		scoreWithHash := effectiveScore * (1.0 + 0.01*uniform)

		if scoreWithHash > bestScore || (scoreWithHash == bestScore && candidate.ID < selected) {
			bestScore = scoreWithHash
			selected = candidate.ID
		}
	}
	return selected
}

func normalizeOpenDomains(candidates []Candidate) []Candidate {
	result := append([]Candidate(nil), candidates...)
	openDomains := make(map[string]bool)
	for _, candidate := range result {
		if candidate.CircuitOpen && candidate.FailureDomain != "" {
			openDomains[candidate.FailureDomain] = true
		}
	}
	for index := range result {
		if openDomains[result[index].FailureDomain] {
			result[index].CircuitOpen = true
		}
	}
	return result
}

func assignmentUsesOpenDomain(assignment Assignment, byID map[string]Candidate) bool {
	for _, candidateID := range []string{assignment.TCP, assignment.UDP} {
		if candidate, exists := byID[candidateID]; exists && candidate.CircuitOpen {
			return true
		}
	}
	return false
}

func activeDomainLoad(
	now time.Time,
	clients []Client,
	byID map[string]Candidate,
	inactiveAfter time.Duration,
) map[string]int {
	result := make(map[string]int)
	for _, client := range clients {
		if client.LastTraffic.IsZero() || now.Sub(client.LastTraffic) > inactiveAfter {
			continue
		}
		tcpID := client.Assignment.TCP
		udpID := client.Assignment.UDP
		var domainTCP string
		if tcpID != "" {
			domainTCP = candidateIDDomain(tcpID, byID)
			result[domainTCP]++
		}
		if udpID != "" {
			domainUDP := candidateIDDomain(udpID, byID)
			if tcpID == "" || domainUDP != domainTCP {
				result[domainUDP]++
			}
		}
	}
	return result
}

func adjustAssignmentLoad(
	load map[string]int,
	domainLoad map[string]int,
	assignment Assignment,
	byID map[string]Candidate,
	delta int,
) {
		tcpID := assignment.TCP
		udpID := assignment.UDP
		if tcpID != "" {
			load[tcpID] += delta
			domainLoad[candidateIDDomain(tcpID, byID)] += delta
		}
		if udpID != "" && udpID != tcpID {
			load[udpID] += delta
		}
		if udpID != "" {
			domainUDP := candidateIDDomain(udpID, byID)
			if tcpID == "" || domainUDP != candidateIDDomain(tcpID, byID) {
				domainLoad[domainUDP] += delta
			}
		}
}

func candidateIDDomain(candidateID string, byID map[string]Candidate) string {
	if candidate, exists := byID[candidateID]; exists {
		return candidateDomain(candidate)
	}
	return legacyCandidateDomain(candidateID)
}

func candidateDomain(candidate Candidate) string {
	if candidate.FailureDomain != "" {
		return candidate.FailureDomain
	}
	return legacyCandidateDomain(candidate.ID)
}

func legacyCandidateDomain(candidateID string) string {
	return "\x00legacy-candidate:" + candidateID
}

func activeLoad(now time.Time, clients []Client, inactiveAfter time.Duration) map[string]int {
	assignments := make(map[string]Assignment, len(clients))
	for _, client := range clients {
		assignments[client.ID] = client.Assignment
	}
	return loadFromAssignments(now, clients, assignments, inactiveAfter)
}

func loadFromAssignments(now time.Time, clients []Client, assignments map[string]Assignment, inactiveAfter time.Duration) map[string]int {
	result := make(map[string]int)
	for _, client := range clients {
		if client.LastTraffic.IsZero() || now.Sub(client.LastTraffic) > inactiveAfter {
			continue
		}
		assignment := assignments[client.ID]
		tcpID := assignment.TCP
		udpID := assignment.UDP
		if tcpID != "" {
			result[tcpID]++
		}
		if udpID != "" && udpID != tcpID {
			result[udpID]++
		}
	}
	return result
}
