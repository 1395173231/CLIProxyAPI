package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
)

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
