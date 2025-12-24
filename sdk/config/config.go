// Package config provides the public SDK configuration API.
//
// It re-exports the server configuration types and helpers so external projects can
// embed CLIProxyAPI without importing internal packages.
package config
import internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"

// SDKConfig represents the application's configuration, loaded from a YAML file.
type SDKConfig struct {
	// ProxyURL is the URL of an optional proxy server to use for outbound requests.
	ProxyURL string `yaml:"proxy-url" json:"proxy-url"`

	// RequestLog enables or disables detailed request logging functionality.
	RequestLog bool `yaml:"request-log" json:"request-log"`

	// APIKeys is a list of keys for authenticating clients to this proxy server.
	APIKeys []string `yaml:"api-keys" json:"api-keys"`

	// Access holds request authentication provider configuration.
	Access AccessConfig `yaml:"auth,omitempty" json:"auth,omitempty"`

	// StickyIndex configures optional persistence for the low-memory message index
	// used by SmartStickySelector to keep sticky routing across restarts.
	StickyIndex StickyIndexConfig `yaml:"sticky-index,omitempty" json:"sticky-index,omitempty"`
}

type SDKConfig = internalconfig.SDKConfig
type AccessConfig = internalconfig.AccessConfig
type AccessProvider = internalconfig.AccessProvider

type Config = internalconfig.Config

type StreamingConfig = internalconfig.StreamingConfig
type TLSConfig = internalconfig.TLSConfig
type RemoteManagement = internalconfig.RemoteManagement
type AmpCode = internalconfig.AmpCode
type PayloadConfig = internalconfig.PayloadConfig
type PayloadRule = internalconfig.PayloadRule
type PayloadModelRule = internalconfig.PayloadModelRule

type GeminiKey = internalconfig.GeminiKey
type CodexKey = internalconfig.CodexKey
type ClaudeKey = internalconfig.ClaudeKey
type VertexCompatKey = internalconfig.VertexCompatKey
type VertexCompatModel = internalconfig.VertexCompatModel
type OpenAICompatibility = internalconfig.OpenAICompatibility
type OpenAICompatibilityAPIKey = internalconfig.OpenAICompatibilityAPIKey
type OpenAICompatibilityModel = internalconfig.OpenAICompatibilityModel

type TLS = internalconfig.TLSConfig

 // StickyIndexConfig defines optional Redis persistence for sticky routing.
 type StickyIndexConfig struct {
 	// RedisEnabled toggles Redis-backed persistence.
 	RedisEnabled bool `yaml:"redis-enabled" json:"redis-enabled"`
 	// RedisAddr is host:port (e.g., "127.0.0.1:6379").
 	RedisAddr string `yaml:"redis-addr,omitempty" json:"redis-addr,omitempty"`
 	// RedisPassword optional password.
 	RedisPassword string `yaml:"redis-password,omitempty" json:"redis-password,omitempty"`
 	// RedisDB database index.
 	RedisDB int `yaml:"redis-db,omitempty" json:"redis-db,omitempty"`
 	// RedisPrefix key prefix (default "msgidx").
 	RedisPrefix string `yaml:"redis-prefix,omitempty" json:"redis-prefix,omitempty"`
 	// TTLSeconds expiration in seconds for bindings; <=0 uses default.
 	TTLSeconds int `yaml:"ttl-seconds,omitempty" json:"ttl-seconds,omitempty"`
 }
const (
	AccessProviderTypeConfigAPIKey = internalconfig.AccessProviderTypeConfigAPIKey
	DefaultAccessProviderName      = internalconfig.DefaultAccessProviderName
	DefaultPanelGitHubRepository   = internalconfig.DefaultPanelGitHubRepository
)

func MakeInlineAPIKeyProvider(keys []string) *AccessProvider {
	return internalconfig.MakeInlineAPIKeyProvider(keys)
}

func LoadConfig(configFile string) (*Config, error) { return internalconfig.LoadConfig(configFile) }

func LoadConfigOptional(configFile string, optional bool) (*Config, error) {
	return internalconfig.LoadConfigOptional(configFile, optional)
}

func SaveConfigPreserveComments(configFile string, cfg *Config) error {
	return internalconfig.SaveConfigPreserveComments(configFile, cfg)
}

func SaveConfigPreserveCommentsUpdateNestedScalar(configFile string, path []string, value string) error {
	return internalconfig.SaveConfigPreserveCommentsUpdateNestedScalar(configFile, path, value)
}

func NormalizeCommentIndentation(data []byte) []byte {
	return internalconfig.NormalizeCommentIndentation(data)
}
