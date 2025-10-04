package db

import "github.com/chenjiaojiao12345-dev/im/pkg/redis"

func NewRedis(addr string, password string) *redis.Conn {
	return redis.New(addr, password)
}
