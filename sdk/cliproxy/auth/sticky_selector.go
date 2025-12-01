package auth

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"math/rand"
	"strings"
	"sync"
	"time"
	"unicode"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

// SmartStickySelector chooses credentials deterministically for Codex based on a
// context fingerprint to preserve upstream per-account caches, and falls back
// to round-robin for other providers or when no context is available.
// Rendezvous (highest-random-weight) hashing provides good balance and stability.
type SmartStickySelector struct {
	mu      sync.Mutex
	offsets map[string]int // fallback round-robin cursor per (provider|model)
	idx     messageIndexStore  // per-message hash -> auth binding index (memory or redis)
}

// NewSmartStickySelector constructs a new sticky selector.
func NewSmartStickySelector() *SmartStickySelector {
	return &SmartStickySelector{
		offsets: make(map[string]int),
		idx:     newMessageIndex(),
	}
}

// Pick implements Selector.
// - For provider "codex":
//  1. Try per-message-hash suggestion;
//  2. If any messages present but no reliable suggestion: RANDOM among available (fairness);
//  3. If no messages: try strong context key (conversation/thread) rendezvous;
//
// - Otherwise: round-robin.
func (s *SmartStickySelector) Pick(_ context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	// Sanity
	filtered := make([]*Auth, 0, len(auths))
	for _, a := range auths {
		if a != nil && !a.Disabled {
			filtered = append(filtered, a)
		}
	}
	if len(filtered) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}

	scope := strings.ToLower(strings.TrimSpace(provider)) + "|" + strings.ToLower(strings.TrimSpace(model))
	var chosen *Auth

	// Sticky selection only for Codex
	if strings.EqualFold(strings.TrimSpace(provider), "codex") {
		// 1) Try per-message hash index suggestion
		msgHashes := extractMessageHashes(opts.OriginalRequest)
		if len(msgHashes) > 0 && s.idx != nil {
			if a := s.idx.SuggestAuth(scope, msgHashes, filtered); a != nil {
				chosen = a
			}
		}

		// 2) If messages exist but no reliable suggestion: RANDOM among available (not "second best")
		if chosen == nil && len(msgHashes) > 0 && len(filtered) > 0 {
			idx := randIntn(len(filtered))
			if idx < 0 || idx >= len(filtered) {
				idx = 0
			}
			chosen = filtered[idx]
		}

		// 4) If chosen, record bindings and return
		if chosen != nil {
			if len(msgHashes) > 0 && s.idx != nil {
				s.idx.Record(scope, msgHashes, chosen.ID)
			}
			return chosen.Clone(), nil
		}
	}

	// Fallback: round-robin by (provider|model)
	k := scope
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.offsets[k]
	if len(filtered) > 0 {
		cur = cur % len(filtered)
	}
	next := (cur + 1) % len(filtered)
	s.offsets[k] = next
	return filtered[cur].Clone(), nil
}

func hash64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// randIntn is overrideable in tests for deterministic random selection.
var randIntn = func(n int) int {
	if n <= 1 {
		return 0
	}
	return rand.Intn(n)
}

// lookup helpers
func lookupString(node any, key string) string {
	if m, ok := node.(map[string]any); ok {
		if v, ok1 := m[key]; ok1 {
			if s, ok2 := v.(string); ok2 {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
func lookupNestedString(node any, k1, k2 string) string {
	if m, ok := node.(map[string]any); ok {
		if v, ok1 := m[k1]; ok1 {
			if mm, ok2 := v.(map[string]any); ok2 {
				if s, ok3 := mm[k2].(string); ok3 {
					return strings.TrimSpace(s)
				}
			}
		}
	}
	return ""
}

// -------------------------
// Low-memory message index
// -------------------------

// messageIndexStore defines persistence operations for sticky selection bindings.
// Implementations: in-memory (messageIndex) and Redis-backed (redisMessageIndex).
type messageIndexStore interface {
	SuggestAuth(scope string, msgHashes []uint64, auths []*Auth) *Auth
	Record(scope string, msgHashes []uint64, authID string)
	InvalidateAuth(scope, authID string) int
}

type msgBinding struct {
	AuthID   string
	Count    int
	LastSeen time.Time
}

type messageIndex struct {
	mu    sync.RWMutex
	byKey map[string]map[uint64]*msgBinding // scope -> (msgHash -> binding)
	ops   uint64
}

func newMessageIndex() *messageIndex {
	return &messageIndex{
		byKey: make(map[string]map[uint64]*msgBinding),
	}
}

const (
	indexMaxPerScope = 100_000       // hard cap per (provider|model)
	indexTTL         = 6 * time.Hour // expire old bindings
	indexScanGC      = 4_096         // max entries scanned per GC pass
)

// SuggestAuth proposes an auth whose messages overlap most with current hashes.
// Requires minimum coverage to avoid spurious matches.
func (idx *messageIndex) SuggestAuth(scope string, msgHashes []uint64, auths []*Auth) *Auth {
	if idx == nil || scope == "" || len(msgHashes) == 0 {
		return nil
	}
	idx.mu.RLock()
	table := idx.byKey[scope]
	if table == nil {
		idx.mu.RUnlock()
		return nil
	}
	scores := make(map[string]int, 8)
	for _, h := range msgHashes {
		if b, ok := table[h]; ok && b != nil && b.AuthID != "" {
			scores[b.AuthID]++
		}
	}
	idx.mu.RUnlock()
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
	// coverage threshold
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

// Record stores bindings from message hashes to the chosen auth id with TTL and periodic GC.
func (idx *messageIndex) Record(scope string, msgHashes []uint64, authID string) {
	if idx == nil || scope == "" || authID == "" || len(msgHashes) == 0 {
		return
	}
	now := time.Now()
	idx.mu.Lock()
	table := idx.byKey[scope]
	if table == nil {
		table = make(map[uint64]*msgBinding, len(msgHashes)*2)
		idx.byKey[scope] = table
	}
	for _, h := range msgHashes {
		if b, ok := table[h]; ok && b != nil {
			if b.AuthID == authID {
				b.Count++
				b.LastSeen = now
			} else {
				// Keep the majority binding; lightly decay on conflict.
				if b.Count <= 0 {
					b.AuthID = authID
					b.Count = 1
					b.LastSeen = now
				} else {
					b.Count--
					if b.Count < 0 {
						b.Count = 0
					}
				}
			}
		} else {
			table[h] = &msgBinding{AuthID: authID, Count: 1, LastSeen: now}
		}
	}
	// periodic GC by ops, and size guard
	idx.ops++
	if idx.ops%1024 == 0 || len(table) > indexMaxPerScope {
		gcCount := 0
		for k, v := range table {
			if now.Sub(v.LastSeen) > indexTTL {
				delete(table, k)
				gcCount++
				if gcCount >= indexScanGC {
					break
				}
			}
		}
		// If still too large, drop oldest scans (bounded pass)
		if len(table) > indexMaxPerScope {
			drop := 0
			oldestCut := now.Add(-indexTTL / 2)
			for k, v := range table {
				if v.LastSeen.Before(oldestCut) {
					delete(table, k)
					drop++
					if drop >= indexScanGC {
						break
					}
				}
			}
		}
	}
	idx.mu.Unlock()
}

// InvalidateAuth removes bindings for a specific auth within a scope (bounded scan).
func (idx *messageIndex) InvalidateAuth(scope, authID string) int {
	if idx == nil || scope == "" || strings.TrimSpace(authID) == "" {
		return 0
	}
	authID = strings.TrimSpace(authID)
	now := time.Now()
	removed := 0
	idx.mu.Lock()
	table := idx.byKey[scope]
	if table != nil {
		scan := 0
		for k, v := range table {
			if v == nil {
				continue
			}
			// also age out stale entries during scan
			if now.Sub(v.LastSeen) > indexTTL {
				delete(table, k)
				removed++
				scan++
				if scan >= indexScanGC {
					break
				}
				continue
			}
			if strings.TrimSpace(v.AuthID) == authID {
				delete(table, k)
				removed++
				scan++
				if scan >= indexScanGC {
					break
				}
			}
		}
	}
	idx.mu.Unlock()
	return removed
}

// InvalidateAuth purges sticky bindings for a given (scope, authID).
func (s *SmartStickySelector) InvalidateAuth(scope, authID string) int {
	if s == nil || s.idx == nil {
		return 0
	}
	return s.idx.InvalidateAuth(scope, authID)
}

const minMessageRuneLen = 16

// extractMessageHashes parses request JSON and returns unique 64-bit hashes
// for per-message user/system text content or responses-style input.
func extractMessageHashes(raw []byte) []uint64 {
	if len(raw) == 0 {
		return nil
	}
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil
	}
	m, ok := root.(map[string]any)
	if !ok {
		return nil
	}
	hashes := make([]uint64, 0, 64)

	// OpenAI-like messages
	if msgsAny, ok := m["messages"]; ok {
		if msgs, ok := msgsAny.([]any); ok {
			for _, mmAny := range msgs {
				mm, ok := mmAny.(map[string]any)
				if !ok {
					continue
				}
				role, _ := mm["role"].(string)
				role = strings.ToLower(strings.TrimSpace(role))
				if role != "user" && role != "system" && role != "" {
					continue
				}
				if c, ok := mm["content"]; ok {
					switch cc := c.(type) {
					case string:
						if s := normalizeText(cc); s != "" {
							hashes = append(hashes, hash64(s))
						}
					case []any:
						for _, part := range cc {
							if pm, ok := part.(map[string]any); ok {
								if t, ok := pm["text"].(string); ok && t != "" {
									if s := normalizeText(t); s != "" {
										hashes = append(hashes, hash64(s))
									}
								} else if s2, ok := pm["content"].(string); ok && s2 != "" {
									if s := normalizeText(s2); s != "" {
										hashes = append(hashes, hash64(s))
									}
								}
							}
						}
					}
				}
			}
		}
	} else if inputAny, ok := m["input"]; ok {
		// Responses-style input
		switch v := inputAny.(type) {
		case string:
			if s := normalizeText(v); s != "" {
				hashes = append(hashes, hash64(s))
			}
		case []any:
			for _, it := range v {
				if mm, ok := it.(map[string]any); ok {
					if t, ok := mm["text"].(string); ok && t != "" {
						if s := normalizeText(t); s != "" {
							hashes = append(hashes, hash64(s))
						}
					} else if c, ok := mm["content"].(string); ok && c != "" {
						if s := normalizeText(c); s != "" {
							hashes = append(hashes, hash64(s))
						}
					}
				}
			}
		}
	}

	// Deduplicate
	if len(hashes) > 1 {
		seen := make(map[uint64]struct{}, len(hashes))
		out := hashes[:0]
		for _, h := range hashes {
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
		hashes = out
	}
	return hashes
}

func normalizeText(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(256)
	prevSpace := false
	textRunes := 0
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		// skip zero-width / null-like characters
		if r == '\u0000' || r == '\uFEFF' {
			continue
		}
		// Count only letters/digits toward the heuristic
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			textRunes++
		}
		b.WriteRune(r)
		if b.Len() >= 4096 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if textRunes < minMessageRuneLen {
		return ""
	}
	return out
}
