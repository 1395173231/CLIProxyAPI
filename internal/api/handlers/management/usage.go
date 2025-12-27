package management

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
)

type usageExportPayload struct {
	Version    int                      `json:"version"`
	ExportedAt time.Time                `json:"exported_at"`
	Usage      usage.StatisticsSnapshot `json:"usage"`
}

type usageImportPayload struct {
	Version int                      `json:"version"`
	Usage   usage.StatisticsSnapshot `json:"usage"`
}

// GetUsageStatistics returns the in-memory request statistics snapshot.
func (h *Handler) GetUsageStatistics(c *gin.Context) {
	var snapshot usage.StatisticsSnapshot
	if h != nil && h.usageStats != nil {
		snapshot = h.usageStats.Snapshot()
	}
	c.JSON(http.StatusOK, gin.H{
		"usage":           snapshot,
		"failed_requests": snapshot.FailureCount,
	})
}

// GetCodexUsage requires explicit auth_id to fetch Codex plan and rate limits.
// Query parameters:
// - auth_id: required specific auth ID (auth file name, with or without .json)
// - refresh: if "true", bypass in-memory cache
func (h *Handler) GetCodexUsage(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
		return
	}
	authID := strings.TrimSpace(c.Query("auth_id"))
	if authID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth_id is required"})
		return
	}
	if strings.HasSuffix(strings.ToLower(authID), ".json") {
		authID = strings.TrimSuffix(authID, ".json")
	}
	refresh := strings.EqualFold(strings.TrimSpace(c.Query("refresh")), "true")

	a, ok := h.authManager.GetByID(authID)
	if !ok || a == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth not found"})
		return
	}
	if a.Disabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth is disabled"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth provider must be codex"})
		return
	}

	data, err := usage.FetchCodexWhamUsage(c.Request.Context(), h.cfg, a, refresh)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	resp := gin.H{
		"auth_id":    a.ID,
		"account_id": "",
		"provider":   a.Provider,
		"usage":      data,
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["account_id"].(string); ok {
			resp["account_id"] = v
		}
		if v, ok := a.Metadata["email"].(string); ok && strings.TrimSpace(v) != "" {
			resp["email"] = v
		}
	}
	c.JSON(http.StatusOK, resp)
}


// ExportUsageStatistics returns a complete usage snapshot for backup/migration.
func (h *Handler) ExportUsageStatistics(c *gin.Context) {
	var snapshot usage.StatisticsSnapshot
	if h != nil && h.usageStats != nil {
		snapshot = h.usageStats.Snapshot()
	}
	c.JSON(http.StatusOK, usageExportPayload{
		Version:    1,
		ExportedAt: time.Now().UTC(),
		Usage:      snapshot,
	})
}

// ImportUsageStatistics merges a previously exported usage snapshot into memory.
func (h *Handler) ImportUsageStatistics(c *gin.Context) {
	if h == nil || h.usageStats == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "usage statistics unavailable"})
		return
	}

	data, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	var payload usageImportPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if payload.Version != 0 && payload.Version != 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported version"})
		return
	}

	result := h.usageStats.MergeSnapshot(payload.Usage)
	snapshot := h.usageStats.Snapshot()
	c.JSON(http.StatusOK, gin.H{
		"added":           result.Added,
		"skipped":         result.Skipped,
		"total_requests":  snapshot.TotalRequests,
		"failed_requests": snapshot.FailureCount,
	})
}
