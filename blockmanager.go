package traefik-regex-block

import (
    "net"
    "time"
)

// BlockStorage defines the interface for managing IP addresses.
type BlockStorage interface {
    IsBlocked(ip net.IP) (bool)
    Block(ip net.IP, minutes int) (error)
    UnBlock(ip net.IP) (error)
}

// ArrayStorage implements BlockStorage using an array.
type ArrayStorage struct {
    ipList map[string]time.Time
}

func (as *ArrayStorage) Block(ip net.IP, minutes int) (error) {
    now := time.Now()
    as.ipList[ip.String()] = now.Add(time.Minute * time.Duration(minutes))
    return nil
}

func (as *ArrayStorage) IsBlocked(ip net.IP) (bool) {
    blockTime, ok := as.ipList[ip.String()]
    if ! ok {
        return false
    }
    if blockTime.Before(time.Now()) {
	delete(as.ipList, ip.String())
        return false
    }
    return true
}

func (as *ArrayStorage) UnBlock(ip net.IP) (error) {
    if as.IsBlocked(ip) {
        delete(as.ipList, ip.String())
    }
    return nil
}

// RedisStorage implements BlockStorage using a Redis connection.
type RedisStorage struct {
    redisHost	string
}

func (db *RedisStorage) Block(ip net.IP, minutes int) (error) {
    return nil
}

func (as *RedisStorage) IsBlocked(ip net.IP) (bool) {
    return false
}

func (as *RedisStorage) UnBlock(ip net.IP) (error) {
    return nil
}

// BlockManager defines the struct for managing IP addresses.
type BlockManager struct {
    storage BlockStorage
}

func ArrayBlockManager() *BlockManager {
    var storage BlockStorage
    storage = &ArrayStorage{
        ipList: make(map[string]time.Time),
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

func (im *BlockManager) Block(ip net.IP, minutes int) (error) {
    return im.storage.Block(ip, minutes)
}

func (im *BlockManager) IsBlocked(ip net.IP) (bool) {
    return im.storage.IsBlocked(ip)
}

func (im *BlockManager) UnBlock(ip net.IP) (error) {
    return im.storage.UnBlock(ip)
}
