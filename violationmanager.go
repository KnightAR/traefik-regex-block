package traefik_regex_block

import (
	"container/list"
	"net"
	"sync"
	"time"
)

// ViolationStorage defines the interface for managing pre-block violation counts.
type ViolationStorage interface {
	AddViolation(ip net.IP, windowSeconds int) (int, error)
	ClearViolations(ip net.IP) error
}

type violationEntry struct {
	ipString  string
	count     int
	expiresAt time.Time
}

type violationListEntry struct {
	entry violationEntry
	elem  *list.Element
}

// ArrayViolationStorage implements ViolationStorage using in-memory storage.
//
// maxViolationIPs controls how many unique IPs can be tracked for violations.
// A value of 0 means unlimited, preserving the original behavior.
// When the limit is reached, the oldest tracked IP is evicted.
type ArrayViolationStorage struct {
	mu              sync.Mutex
	violations      map[string]*violationListEntry
	order           *list.List
	maxViolationIPs int
}

func (as *ArrayViolationStorage) AddViolation(ip net.IP, windowSeconds int) (int, error) {
	as.mu.Lock()
	defer as.mu.Unlock()

	if windowSeconds <= 0 {
		windowSeconds = 300
	}

	now := time.Now()
	ipString := ip.String()

	as.pruneExpiredLocked(now)

	trackedEntry, ok := as.violations[ipString]
	if !ok || trackedEntry.entry.expiresAt.Before(now) {
		entry := violationEntry{
			ipString:  ipString,
			count:     1,
			expiresAt: now.Add(time.Second * time.Duration(windowSeconds)),
		}

		if ok {
			as.order.Remove(trackedEntry.elem)
		}

		elem := as.order.PushBack(ipString)
		as.violations[ipString] = &violationListEntry{
			entry: entry,
			elem:  elem,
		}

		as.enforceMaxViolationIPsLocked()
		return entry.count, nil
	}

	trackedEntry.entry.count++
	trackedEntry.entry.expiresAt = now.Add(time.Second * time.Duration(windowSeconds))

	// Treat each new violation as recent activity for eviction purposes.
	as.order.MoveToBack(trackedEntry.elem)

	return trackedEntry.entry.count, nil
}

func (as *ArrayViolationStorage) ClearViolations(ip net.IP) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	ipString := ip.String()
	as.deleteViolationLocked(ipString)

	return nil
}

func (as *ArrayViolationStorage) pruneExpiredLocked(now time.Time) {
	for ipString, trackedEntry := range as.violations {
		if trackedEntry.entry.expiresAt.Before(now) {
			as.deleteViolationLocked(ipString)
		}
	}
}

func (as *ArrayViolationStorage) enforceMaxViolationIPsLocked() {
	if as.maxViolationIPs <= 0 {
		return
	}

	for len(as.violations) > as.maxViolationIPs {
		front := as.order.Front()
		if front == nil {
			return
		}

		ipString, ok := front.Value.(string)
		if !ok {
			as.order.Remove(front)
			continue
		}

		as.deleteViolationLocked(ipString)
	}
}

func (as *ArrayViolationStorage) deleteViolationLocked(ipString string) {
	trackedEntry, ok := as.violations[ipString]
	if !ok {
		return
	}

	as.order.Remove(trackedEntry.elem)
	delete(as.violations, ipString)
}

// RedisViolationStorage implements ViolationStorage using a Redis connection.
// Placeholder for future storage backends.
type RedisViolationStorage struct {
	redisHost string
}

func (db *RedisViolationStorage) AddViolation(ip net.IP, windowSeconds int) (int, error) {
	return 0, nil
}

func (db *RedisViolationStorage) ClearViolations(ip net.IP) error {
	return nil
}

// ViolationManager defines the struct for managing violation counts.
type ViolationManager struct {
	storage ViolationStorage
}

func ArrayViolationManager(maxViolationIPs int) *ViolationManager {
	if maxViolationIPs < 0 {
		maxViolationIPs = 0
	}

	var storage ViolationStorage
	storage = &ArrayViolationStorage{
		violations:      make(map[string]*violationListEntry),
		order:           list.New(),
		maxViolationIPs: maxViolationIPs,
	}

	return &ViolationManager{
		storage: storage,
	}
}

func RedisViolationManager(host string) *ViolationManager {
	var storage ViolationStorage
	storage = &RedisViolationStorage{
		redisHost: host,
	}

	return &ViolationManager{
		storage: storage,
	}
}

func (vm *ViolationManager) AddViolation(ip net.IP, windowSeconds int) (int, error) {
	return vm.storage.AddViolation(ip, windowSeconds)
}

func (vm *ViolationManager) ClearViolations(ip net.IP) error {
	return vm.storage.ClearViolations(ip)
}
