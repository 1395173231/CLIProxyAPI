// Package auth adds an optional Redis-backed persistence for the low-memory message index
// used by SmartStickySelector. This preserves sticky routing across restarts when enabled.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisOptions configures the Redis-backed message index.
// Enable it by constructing a selector via NewSmartStickySelectorWithRedis.
type RedisOptions struct {
	// Addr is the Redis address, e.g. "127.0.0.1:6379"
	Addr string
	// Password is the optional password for Redis AUTH
	Password string
	// DB selects the Redis database index
	DB int
	// Prefix scopes keys, default: "msgidx"
	Prefix string
	// TTL controls expiry for bindings; <=0 uses the package default indexTTL
	TTL time.Duration
}

// NewSmartStickySelectorWithRedis constructs a SmartStickySelector that persists
// the message-hash bindings in Redis using the provided options.
//
// The in-memory coverage/best-selection logic remains identical to the memory index
// (including coverage thresholds), but reads come from Redis on-demand so the
// sticky affinity survives process restarts.
func NewSmartStickySelectorWithRedis(opts RedisOptions) *SmartStickySelector {
	idx := newRedisMessageIndex(opts)
	return &SmartStickySelector{
		offsets: make(map[string]int),
		idx:     idx,
	}
}

type redisMessageIndex struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

func newRedisMessageIndex(opts RedisOptions) *redisMessageIndex {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = indexTTL
	}
	prefix := strings.TrimSpace(opts.Prefix)
	if prefix == "" {
		prefix = "msgidx"
	}
	client := redis.NewClient(&redis.Options{
		Addr:     strings.TrimSpace(opts.Addr),
		Password: opts.Password,
		DB:       opts.DB,
	})
	// Best-effort warmup; ignore error to avoid hard-failing startup.
	_ = client.Ping(context.Background()).Err()

	return &redisMessageIndex{
		client: client,
		prefix: prefix,
		ttl:    ttl,
	}
}

func (r *redisMessageIndex) key(scope string, hash uint64) string {
	scope = strings.ToLower(strings.TrimSpace(scope))
	return fmt.Sprintf("%s:%s:%d", r.prefix, scope, hash)
}

// SuggestAuth proposes an auth whose messages overlap most with current hashes.
// Mirrors the in-memory coverage behavior; reads are fetched via MGET.
func (r *redisMessageIndex) SuggestAuth(scope string, msgHashes []uint64, auths []*Auth) *Auth {
	if r == nil || scope == "" || len(msgHashes) == 0 {
		return nil
	}
	ctx := context.Background()
	keys := make([]string, 0, len(msgHashes))
	for _, h := range msgHashes {
		keys = append(keys, r.key(scope, h))
	}
	vals, err := r.client.MGet(ctx, keys...).Result()
	if err != nil || len(vals) == 0 {
		return nil
	}

	scores := make(map[string]int, 8)
	for _, v := range vals {
		if v == nil {
			continue
		}
		var b msgBinding
		switch vv := v.(type) {
		case string:
			_ = json.Unmarshal([]byte(vv), &b)
		case []byte:
			_ = json.Unmarshal(vv, &b)
		default:
			continue
		}
		if id := strings.TrimSpace(b.AuthID); id != "" {
			scores[id]++
		}
	}
	if len(scores) == 0 {
		return nil
	}

	// pick best
	bestID := ""
	bestScore := 0
	for id, sc := range scores {
		if sc > bestScore {
			bestScore = sc
			bestID = id
		}
	}

	// coverage threshold (same as memory index)
	minCover := 0
	switch {
	case len(msgHashes) >= 9:
		minCover = len(msgHashes) / 3
	case len(msgHashes) >= 4:
		minCover = 2
	case len(msgHashes) >= 2:
		minCover = 1
	default:
		minCover = 0
	}
	if bestScore < minCover {
		return nil
	}

	// ensure the suggested auth is in current candidate set and enabled
	bestID = strings.TrimSpace(bestID)
	for _, a := range auths {
		if a != nil && !a.Disabled && strings.TrimSpace(a.ID) == bestID {
			return a
		}
	}
	return nil
}

// Record stores per-hash bindings with TTL. It preserves the "majority binding"
// behavior: increment when same auth, otherwise lightly decay and switch if count <= 0.
func (r *redisMessageIndex) Record(scope string, msgHashes []uint64, authID string) {
	if r == nil || scope == "" || authID == "" || len(msgHashes) == 0 {
		return
	}
	ctx := context.Background()
	now := time.Now()
	authID = strings.TrimSpace(authID)

	for _, h := range msgHashes {
		key := r.key(scope, h)

		// read existing
		var b msgBinding
		if raw, err := r.client.Get(ctx, key).Bytes(); err == nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, &b)
		}

		if strings.TrimSpace(b.AuthID) == authID {
			if b.Count < 0 {
				b.Count = 0
			}
			b.Count++
			b.LastSeen = now
		} else if strings.TrimSpace(b.AuthID) == "" {
			b.AuthID = authID
			b.Count = 1
			b.LastSeen = now
		} else {
			// conflict: decay; if reaches 0, switch to new auth
			b.Count--
			if b.Count <= 0 {
				b.AuthID = authID
				b.Count = 1
			}
			b.LastSeen = now
		}

		if encoded, err := json.Marshal(&b); err == nil {
			_ = r.client.Set(ctx, key, encoded, r.ttl).Err()
		}
	}
}

// InvalidateAuth scans per-scope keys and deletes those bound to the given auth.
// The scan is bounded by indexScanGC to avoid excessive work.
func (r *redisMessageIndex) InvalidateAuth(scope, authID string) int {
	if r == nil || scope == "" || strings.TrimSpace(authID) == "" {
		return 0
	}
	ctx := context.Background()
	scope = strings.ToLower(strings.TrimSpace(scope))
	authID = strings.TrimSpace(authID)

	pattern := fmt.Sprintf("%s:%s:*", r.prefix, scope)
	var cursor uint64
	removed := 0
	scanned := 0

	for {
		keys, next, err := r.client.Scan(ctx, cursor, pattern, 512).Result()
		if err != nil {
			break
		}
		cursor = next
		if len(keys) == 0 && next == 0 {
			break
		}
		if len(keys) == 0 {
			if cursor == 0 {
				break
			}
			continue
		}

		vals, err := r.client.MGet(ctx, keys...).Result()
		if err != nil {
			break
		}
		for i, v := range vals {
			if v == nil {
				continue
			}
			scanned++
			var b msgBinding
			switch vv := v.(type) {
			case string:
				_ = json.Unmarshal([]byte(vv), &b)
			case []byte:
				_ = json.Unmarshal(vv, &b)
			default:
				continue
			}
			if strings.TrimSpace(b.AuthID) == authID {
				_ = r.client.Del(ctx, keys[i]).Err()
				removed++
				if removed >= indexScanGC {
					return removed
				}
			} else {
				// opportunistic TTL-based cleanup for stale bindings
				if time.Since(b.LastSeen) > r.ttl {
					_ = r.client.Del(ctx, keys[i]).Err()
				}
			}
			if scanned >= indexScanGC {
				return removed
			}
		}
		if cursor == 0 {
			break
		}
	}
	return removed
}