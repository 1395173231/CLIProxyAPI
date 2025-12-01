package util

import (
	"encoding/json"
	"strings"
	"sync"
)

var (
	badImageURLSet   sync.Map
	whiteImageOnce   sync.Once
	whiteImageDataURL string
)

func whiteDataURL() string {
	whiteImageOnce.Do(func() {
		b64, _ := CreateWhiteImageBase64("1:1")
		if strings.TrimSpace(b64) != "" {
			whiteImageDataURL = "data:image/png;base64," + b64
		} else {
			// Fallback to a minimal 1x1 transparent PNG if generation failed (pre-encoded)
			whiteImageDataURL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGP4BwQACfsD/XY6u3kAAAAASUVORK5CYII="
		}
	})
	return whiteImageDataURL
}

func normalizeURL(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

// AddBadImageURL records a URL that should be filtered from future requests.
func AddBadImageURL(u string) {
	u = normalizeURL(u)
	if u == "" {
		return
	}
	badImageURLSet.Store(u, struct{}{})
}

// IsBadImageURL checks if the URL was previously recorded as invalid.
func IsBadImageURL(u string) bool {
	u = normalizeURL(u)
	if u == "" {
		return false
	}
	_, ok := badImageURLSet.Load(u)
	return ok
}

// SanitizeImageURLsJSON replaces any blacklisted image URL occurrences in a JSON payload
// with a valid inline data URL to avoid upstream download failures.
// It looks for keys: "image_url" (string or object with "url") and generic "url".
func SanitizeImageURLsJSON(raw []byte) ([]byte, bool) {
	if len(raw) == 0 {
		return raw, false
	}
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return raw, false
	}
	changed := sanitizeNode(&root)
	if !changed {
		return raw, false
	}
	out, err := json.Marshal(root)
	if err != nil {
		return raw, false
	}
	return out, true
}

func sanitizeNode(n *any) bool {
	changed := false
	switch v := (*n).(type) {
	case map[string]any:
		for k, val := range v {
			// Handle image_url cases
			if k == "image_url" {
				switch t := val.(type) {
				case string:
					if IsBadImageURL(t) {
						v[k] = whiteDataURL()
						changed = true
						continue
					}
				case map[string]any:
					if u, ok := t["url"].(string); ok && IsBadImageURL(u) {
						t["url"] = whiteDataURL()
						changed = true
					}
				}
			}
			// Generic "url" key case
			if k == "url" {
				if s, ok := val.(string); ok && IsBadImageURL(s) {
					v[k] = whiteDataURL()
					changed = true
					continue
				}
			}
			// Recurse
			if sanitizeNode(&val) {
				v[k] = val
				changed = true
			}
		}
	case []any:
		for i := range v {
			if sanitizeNode(&v[i]) {
				changed = true
			}
		}
	default:
	}
	return changed
}