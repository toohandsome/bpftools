// Package parsers - Redis命令表和数据库状态跟踪器
package parsers

import (
	"strings"
)

// 创建Redis命令表
func NewRedisCommandTable() *RedisCommandTable {
	table := &RedisCommandTable{
		commands: make(map[string]*RedisCommandMeta),
	}
	table.initializeCommands()
	return table
}

// GetCommand 获取命令元数据
func (t *RedisCommandTable) GetCommand(command string) *RedisCommandMeta {
	t.mu.RLock()
	defer t.mu.RUnlock()

	cmd := strings.ToLower(command)
	return t.commands[cmd]
}

// initializeCommands 初始化Redis命令表（参考myRedisCapturer的命令表）
func (t *RedisCommandTable) initializeCommands() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// 字符串操作命令
	t.commands["get"] = &RedisCommandMeta{Name: "GET", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["set"] = &RedisCommandMeta{Name: "SET", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["setnx"] = &RedisCommandMeta{Name: "SETNX", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["setex"] = &RedisCommandMeta{Name: "SETEX", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["psetex"] = &RedisCommandMeta{Name: "PSETEX", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["getex"] = &RedisCommandMeta{Name: "GETEX", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["getdel"] = &RedisCommandMeta{Name: "GETDEL", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["append"] = &RedisCommandMeta{Name: "APPEND", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["strlen"] = &RedisCommandMeta{Name: "STRLEN", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["incr"] = &RedisCommandMeta{Name: "INCR", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["decr"] = &RedisCommandMeta{Name: "DECR", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["incrby"] = &RedisCommandMeta{Name: "INCRBY", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["decrby"] = &RedisCommandMeta{Name: "DECRBY", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["incrbyfloat"] = &RedisCommandMeta{Name: "INCRBYFLOAT", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["getset"] = &RedisCommandMeta{Name: "GETSET", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["mget"] = &RedisCommandMeta{Name: "MGET", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: -1, KeyStep: 1, IsRead: true}
	t.commands["mset"] = &RedisCommandMeta{Name: "MSET", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: -1, KeyStep: 2, IsWrite: true}
	t.commands["msetnx"] = &RedisCommandMeta{Name: "MSETNX", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: -1, KeyStep: 2, IsWrite: true}

	// 键操作命令
	t.commands["del"] = &RedisCommandMeta{Name: "DEL", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: -1, KeyStep: 1, IsWrite: true}
	t.commands["unlink"] = &RedisCommandMeta{Name: "UNLINK", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: -1, KeyStep: 1, IsWrite: true}
	t.commands["exists"] = &RedisCommandMeta{Name: "EXISTS", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: -1, KeyStep: 1, IsRead: true}
	t.commands["expire"] = &RedisCommandMeta{Name: "EXPIRE", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["expireat"] = &RedisCommandMeta{Name: "EXPIREAT", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["pexpire"] = &RedisCommandMeta{Name: "PEXPIRE", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["pexpireat"] = &RedisCommandMeta{Name: "PEXPIREAT", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["ttl"] = &RedisCommandMeta{Name: "TTL", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["pttl"] = &RedisCommandMeta{Name: "PTTL", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["persist"] = &RedisCommandMeta{Name: "PERSIST", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["type"] = &RedisCommandMeta{Name: "TYPE", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["rename"] = &RedisCommandMeta{Name: "RENAME", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 2, KeyStep: 1, IsWrite: true}
	t.commands["renamenx"] = &RedisCommandMeta{Name: "RENAMENX", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 2, KeyStep: 1, IsWrite: true}

	// 列表操作命令
	t.commands["lpush"] = &RedisCommandMeta{Name: "LPUSH", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["rpush"] = &RedisCommandMeta{Name: "RPUSH", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["lpushx"] = &RedisCommandMeta{Name: "LPUSHX", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["rpushx"] = &RedisCommandMeta{Name: "RPUSHX", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["lpop"] = &RedisCommandMeta{Name: "LPOP", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["rpop"] = &RedisCommandMeta{Name: "RPOP", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["llen"] = &RedisCommandMeta{Name: "LLEN", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["lindex"] = &RedisCommandMeta{Name: "LINDEX", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["lset"] = &RedisCommandMeta{Name: "LSET", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["lrange"] = &RedisCommandMeta{Name: "LRANGE", MinArgs: 4, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["ltrim"] = &RedisCommandMeta{Name: "LTRIM", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["lrem"] = &RedisCommandMeta{Name: "LREM", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["linsert"] = &RedisCommandMeta{Name: "LINSERT", MinArgs: 5, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}

	// 集合操作命令
	t.commands["sadd"] = &RedisCommandMeta{Name: "SADD", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["srem"] = &RedisCommandMeta{Name: "SREM", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["smembers"] = &RedisCommandMeta{Name: "SMEMBERS", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["sismember"] = &RedisCommandMeta{Name: "SISMEMBER", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["scard"] = &RedisCommandMeta{Name: "SCARD", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["spop"] = &RedisCommandMeta{Name: "SPOP", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["srandmember"] = &RedisCommandMeta{Name: "SRANDMEMBER", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["sinter"] = &RedisCommandMeta{Name: "SINTER", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: -1, KeyStep: 1, IsRead: true}
	t.commands["sunion"] = &RedisCommandMeta{Name: "SUNION", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: -1, KeyStep: 1, IsRead: true}
	t.commands["sdiff"] = &RedisCommandMeta{Name: "SDIFF", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: -1, KeyStep: 1, IsRead: true}

	// 哈希操作命令
	t.commands["hset"] = &RedisCommandMeta{Name: "HSET", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["hget"] = &RedisCommandMeta{Name: "HGET", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["hmset"] = &RedisCommandMeta{Name: "HMSET", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["hmget"] = &RedisCommandMeta{Name: "HMGET", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["hgetall"] = &RedisCommandMeta{Name: "HGETALL", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["hdel"] = &RedisCommandMeta{Name: "HDEL", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["hlen"] = &RedisCommandMeta{Name: "HLEN", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["hexists"] = &RedisCommandMeta{Name: "HEXISTS", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["hkeys"] = &RedisCommandMeta{Name: "HKEYS", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["hvals"] = &RedisCommandMeta{Name: "HVALS", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["hincrby"] = &RedisCommandMeta{Name: "HINCRBY", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["hincrbyfloat"] = &RedisCommandMeta{Name: "HINCRBYFLOAT", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}

	// 有序集合操作命令
	t.commands["zadd"] = &RedisCommandMeta{Name: "ZADD", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["zrem"] = &RedisCommandMeta{Name: "ZREM", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["zcard"] = &RedisCommandMeta{Name: "ZCARD", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["zscore"] = &RedisCommandMeta{Name: "ZSCORE", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["zrank"] = &RedisCommandMeta{Name: "ZRANK", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["zrevrank"] = &RedisCommandMeta{Name: "ZREVRANK", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["zrange"] = &RedisCommandMeta{Name: "ZRANGE", MinArgs: 4, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["zrevrange"] = &RedisCommandMeta{Name: "ZREVRANGE", MinArgs: 4, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["zrangebyscore"] = &RedisCommandMeta{Name: "ZRANGEBYSCORE", MinArgs: 4, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["zincrby"] = &RedisCommandMeta{Name: "ZINCRBY", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}

	// 位操作命令
	t.commands["setbit"] = &RedisCommandMeta{Name: "SETBIT", MinArgs: 4, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["getbit"] = &RedisCommandMeta{Name: "GETBIT", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["bitcount"] = &RedisCommandMeta{Name: "BITCOUNT", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["bitpos"] = &RedisCommandMeta{Name: "BITPOS", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}

	// 管理命令
	t.commands["select"] = &RedisCommandMeta{Name: "SELECT", MinArgs: 2, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["ping"] = &RedisCommandMeta{Name: "PING", MinArgs: 1, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["echo"] = &RedisCommandMeta{Name: "ECHO", MinArgs: 2, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["info"] = &RedisCommandMeta{Name: "INFO", MinArgs: 1, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["config"] = &RedisCommandMeta{Name: "CONFIG", MinArgs: 2, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["flushdb"] = &RedisCommandMeta{Name: "FLUSHDB", MinArgs: 1, Flags: "write", FirstKey: 0, LastKey: 0, KeyStep: 0, IsWrite: true}
	t.commands["flushall"] = &RedisCommandMeta{Name: "FLUSHALL", MinArgs: 1, Flags: "write", FirstKey: 0, LastKey: 0, KeyStep: 0, IsWrite: true}
	t.commands["auth"] = &RedisCommandMeta{Name: "AUTH", MinArgs: 2, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["quit"] = &RedisCommandMeta{Name: "QUIT", MinArgs: 1, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}

	// 扫描命令
	t.commands["scan"] = &RedisCommandMeta{Name: "SCAN", MinArgs: 2, Flags: "readonly", FirstKey: 0, LastKey: 0, KeyStep: 0, IsRead: true}
	t.commands["sscan"] = &RedisCommandMeta{Name: "SSCAN", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["hscan"] = &RedisCommandMeta{Name: "HSCAN", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["zscan"] = &RedisCommandMeta{Name: "ZSCAN", MinArgs: 3, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["keys"] = &RedisCommandMeta{Name: "KEYS", MinArgs: 2, Flags: "readonly", FirstKey: 0, LastKey: 0, KeyStep: 0, IsRead: true}

	// 事务命令
	t.commands["multi"] = &RedisCommandMeta{Name: "MULTI", MinArgs: 1, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["exec"] = &RedisCommandMeta{Name: "EXEC", MinArgs: 1, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["discard"] = &RedisCommandMeta{Name: "DISCARD", MinArgs: 1, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["watch"] = &RedisCommandMeta{Name: "WATCH", MinArgs: 2, Flags: "admin", FirstKey: 1, LastKey: -1, KeyStep: 1, IsAdmin: true}
	t.commands["unwatch"] = &RedisCommandMeta{Name: "UNWATCH", MinArgs: 1, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}

	// 发布订阅命令
	t.commands["publish"] = &RedisCommandMeta{Name: "PUBLISH", MinArgs: 3, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["subscribe"] = &RedisCommandMeta{Name: "SUBSCRIBE", MinArgs: 2, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["unsubscribe"] = &RedisCommandMeta{Name: "UNSUBSCRIBE", MinArgs: 1, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["psubscribe"] = &RedisCommandMeta{Name: "PSUBSCRIBE", MinArgs: 2, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["punsubscribe"] = &RedisCommandMeta{Name: "PUNSUBSCRIBE", MinArgs: 1, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}

	// 脚本命令
	t.commands["eval"] = &RedisCommandMeta{Name: "EVAL", MinArgs: 3, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["evalsha"] = &RedisCommandMeta{Name: "EVALSHA", MinArgs: 3, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}
	t.commands["script"] = &RedisCommandMeta{Name: "SCRIPT", MinArgs: 2, Flags: "admin", FirstKey: 0, LastKey: 0, KeyStep: 0, IsAdmin: true}

	// HyperLogLog命令
	t.commands["pfadd"] = &RedisCommandMeta{Name: "PFADD", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["pfcount"] = &RedisCommandMeta{Name: "PFCOUNT", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: -1, KeyStep: 1, IsRead: true}
	t.commands["pfmerge"] = &RedisCommandMeta{Name: "PFMERGE", MinArgs: 2, Flags: "write", FirstKey: 1, LastKey: -1, KeyStep: 1, IsWrite: true}

	// 地理位置命令
	t.commands["geoadd"] = &RedisCommandMeta{Name: "GEOADD", MinArgs: 5, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["geopos"] = &RedisCommandMeta{Name: "GEOPOS", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["geodist"] = &RedisCommandMeta{Name: "GEODIST", MinArgs: 4, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["georadius"] = &RedisCommandMeta{Name: "GEORADIUS", MinArgs: 6, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}

	// 流命令
	t.commands["xadd"] = &RedisCommandMeta{Name: "XADD", MinArgs: 5, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
	t.commands["xread"] = &RedisCommandMeta{Name: "XREAD", MinArgs: 4, Flags: "readonly", FirstKey: 0, LastKey: 0, KeyStep: 0, IsRead: true}
	t.commands["xlen"] = &RedisCommandMeta{Name: "XLEN", MinArgs: 2, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["xrange"] = &RedisCommandMeta{Name: "XRANGE", MinArgs: 4, Flags: "readonly", FirstKey: 1, LastKey: 1, KeyStep: 1, IsRead: true}
	t.commands["xdel"] = &RedisCommandMeta{Name: "XDEL", MinArgs: 3, Flags: "write", FirstKey: 1, LastKey: 1, KeyStep: 1, IsWrite: true}
}
