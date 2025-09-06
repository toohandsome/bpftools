package monitor

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ProcessSelector struct {
	PID  int
	Name string
}

func (ps ProcessSelector) Match(pid int, comm string) bool {
	if ps.PID != 0 {
		matches := pid == ps.PID
		log.Printf("selector Match: target PID=%d, event PID=%d, matches=%v", ps.PID, pid, matches)
		return matches
	}
	if ps.Name != "" {
		commMatches := comm == ps.Name
		procMatches := processNameMatches(pid, ps.Name)
		matches := commMatches || procMatches
		log.Printf("selector Match: target Name=%s, event comm=%s, commMatches=%v, procMatches=%v, matches=%v", ps.Name, comm, commMatches, procMatches, matches)
		return matches
	}
	// Monitor all processes if no filter specified
	log.Printf("selector Match: no filter, monitoring all processes for PID=%d", pid)
	return true
}

func processNameMatches(pid int, name string) bool {
	exe := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	b, err := os.ReadFile(exe)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == name
}
