package traefik_regex_block

import (
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
	count     int
	expiresAt time.Time
}

// ArrayViolationStorage implements ViolationStorage using in-memory storage.
type ArrayViolationStorage struct {
	mu         sync.Mutex
	violations map[string]violationEntry
}

func (as *ArrayViolationStorage) AddViolation(ip net.IP, windowSeconds int) (int, error) {
	as.mu.Lock()
	defer as.mu.Unlock()

	if windowSeconds <= 0 {
		windowSeconds = 300
	}

	now := time.Now()
	ipString := ip.String()
	entry, ok := as.violations[ipString]

	if !ok || entry.expiresAt.Before(now) {
		entry = violationEntry{
			count:     1,
			expiresAt: now.Add(time.Second * time.Duration(windowSeconds)),
		}
	} else {
		entry.count++
	}

	as.violations[ipString] = entry
	as.pruneExpiredLocked(now)

	return entry.count, nil
}

func (as *ArrayViolationStorage) ClearViolations(ip net.IP) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	delete(as.violations, ip.String())
	return nil
}

func (as *ArrayViolationStorage) pruneExpiredLocked(now time.Time) {
	for ipString, entry := range as.violations {
		if entry.expiresAt.Before(now) {
			delete(as.violations, ipString)
		}
	}
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

func ArrayViolationManager() *ViolationManager {
	var storage ViolationStorage
	storage = &ArrayViolationStorage{
		violations: make(map[string]violationEntry),
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
