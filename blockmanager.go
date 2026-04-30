package traefik_regex_block

import (
	"container/list"
	"net"
	"sync"
	"time"
)

// BlockStorage defines the interface for managing blocked IP addresses.
type BlockStorage interface {
	IsBlocked(ip net.IP) bool
	Block(ip net.IP, minutes int) error
	UnBlock(ip net.IP) error
	CountBlocked() int
}

type blockEntry struct {
	ip        string
	expiresAt time.Time
	createdAt time.Time
}

// ArrayStorage implements BlockStorage using in-memory storage.
// maxBlockedIPs <= 0 means unlimited.
type ArrayStorage struct {
	mu            sync.Mutex
	ipList        map[string]*list.Element
	order         *list.List
	maxBlockedIPs int
}

func (as *ArrayStorage) Block(ip net.IP, minutes int) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	now := time.Now()
	ipString := ip.String()
	expiresAt := now.Add(time.Minute * time.Duration(minutes))

	if existing, ok := as.ipList[ipString]; ok {
		entry := existing.Value.(*blockEntry)
		entry.expiresAt = expiresAt
		// Treat a renewed block as fresh for eviction order.
		entry.createdAt = now
		as.order.MoveToBack(existing)
		return nil
	}

	as.pruneExpiredLocked(now)

	if as.maxBlockedIPs > 0 {
		for len(as.ipList) >= as.maxBlockedIPs {
			as.evictOldestLocked()
		}
	}

	entry := &blockEntry{
		ip:        ipString,
		expiresAt: expiresAt,
		createdAt: now,
	}

	element := as.order.PushBack(entry)
	as.ipList[ipString] = element

	return nil
}

func (as *ArrayStorage) IsBlocked(ip net.IP) bool {
	as.mu.Lock()
	defer as.mu.Unlock()

	ipString := ip.String()
	element, ok := as.ipList[ipString]
	if !ok {
		return false
	}

	entry := element.Value.(*blockEntry)
	if entry.expiresAt.Before(time.Now()) {
		as.removeElementLocked(element)
		return false
	}

	return true
}

func (as *ArrayStorage) UnBlock(ip net.IP) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	ipString := ip.String()
	if element, ok := as.ipList[ipString]; ok {
		as.removeElementLocked(element)
	}

	return nil
}

func (as *ArrayStorage) CountBlocked() int {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.pruneExpiredLocked(time.Now())
	return len(as.ipList)
}

func (as *ArrayStorage) pruneExpiredLocked(now time.Time) {
	for element := as.order.Front(); element != nil; {
		next := element.Next()
		entry := element.Value.(*blockEntry)
		if entry.expiresAt.Before(now) {
			as.removeElementLocked(element)
		}
		element = next
	}
}

func (as *ArrayStorage) evictOldestLocked() {
	oldest := as.order.Front()
	if oldest == nil {
		return
	}
	as.removeElementLocked(oldest)
}

func (as *ArrayStorage) removeElementLocked(element *list.Element) {
	entry := element.Value.(*blockEntry)
	delete(as.ipList, entry.ip)
	as.order.Remove(element)
}

// RedisStorage implements BlockStorage using a Redis connection.
// Placeholder for future storage backends.
type RedisStorage struct {
	redisHost string
}

func (db *RedisStorage) Block(ip net.IP, minutes int) error {
	return nil
}

func (db *RedisStorage) IsBlocked(ip net.IP) bool {
	return false
}

func (db *RedisStorage) UnBlock(ip net.IP) error {
	return nil
}

func (db *RedisStorage) CountBlocked() int {
	return 0
}

// BlockManager defines the struct for managing blocked IP addresses.
type BlockManager struct {
	storage BlockStorage
}

func ArrayBlockManager(maxBlockedIPs int) *BlockManager {
	var storage BlockStorage
	storage = &ArrayStorage{
		ipList:        make(map[string]*list.Element),
		order:         list.New(),
		maxBlockedIPs: maxBlockedIPs,
	}

	return &BlockManager{
		storage: storage,
	}
}

func RedisBlockManager(host string) *BlockManager {
	var storage BlockStorage
	storage = &RedisStorage{
		redisHost: host,
	}

	return &BlockManager{
		storage: storage,
	}
}

func (im *BlockManager) Block(ip net.IP, minutes int) error {
	return im.storage.Block(ip, minutes)
}

func (im *BlockManager) IsBlocked(ip net.IP) bool {
	return im.storage.IsBlocked(ip)
}

func (im *BlockManager) UnBlock(ip net.IP) error {
	return im.storage.UnBlock(ip)
}

func (im *BlockManager) CountBlocked() int {
	return im.storage.CountBlocked()
}
