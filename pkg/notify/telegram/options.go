package telegram

import (
	"os"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

const (
	// EnvBotToken is the environment variable for bot token.
	EnvBotToken = "TELEGRAM_BOT_TOKEN"

	// EnvChatID is the environment variable for chat ID.
	EnvChatID = "TELEGRAM_CHAT_ID"

	// DefaultMaxMessageBytes is Telegram's limit for text messages.
	DefaultMaxMessageBytes = 4000

	// DefaultMaxRetries for rate-limited requests.
	DefaultMaxRetries = 20

	// DefaultRateLimit requests per second (Telegram limit is 30/s).
	DefaultRateLimit = 25

	// DefaultHTTPTimeout for HTTP requests to Telegram API.
	DefaultHTTPTimeout = 5 * time.Minute
)

// Config holds the configuration for the Telegram client.
type Config struct {
	// BotToken is the Telegram Bot API token.
	// If empty, reads from TELEGRAM_BOT_TOKEN environment variable.
	BotToken string

	// ChatID is the target chat/group ID.
	// If zero, reads from TELEGRAM_CHAT_ID environment variable.
	ChatID int64

	// MaxRetries is the maximum number of retry attempts for rate-limited requests.
	MaxRetries int

	// RateLimit is the maximum requests per second.
	RateLimit int

	// HTTPTimeout is the timeout for HTTP requests to Telegram API.
	HTTPTimeout time.Duration

	// MaxMessageBytes is the maximum message size before auto-converting to file.
	MaxMessageBytes int
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		MaxRetries:      DefaultMaxRetries,
		RateLimit:       DefaultRateLimit,
		HTTPTimeout:     DefaultHTTPTimeout,
		MaxMessageBytes: DefaultMaxMessageBytes,
	}
}

// LoadFromEnv populates empty Config fields from environment variables.
func (c *Config) LoadFromEnv() error {
	if c.BotToken == "" {
		c.BotToken = os.Getenv(EnvBotToken)
	}
	if c.ChatID == 0 {
		chatIDStr := os.Getenv(EnvChatID)
		if chatIDStr != "" {
			chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
			if err != nil {
				return errors.Wrap(err, "invalid TELEGRAM_CHAT_ID")
			}
			c.ChatID = chatID
		}
	}
	return nil
}

// Validate checks that required configuration is present.
func (c *Config) Validate() error {
	if c.BotToken == "" {
		return errors.New("telegram bot token is required")
	}
	if c.ChatID == 0 {
		return errors.New("telegram chat ID is required")
	}
	return nil
}

// Option is a functional option for configuring the Client.
type Option func(*Config)

// WithBotToken sets the bot token.
func WithBotToken(token string) Option {
	return func(c *Config) {
		c.BotToken = token
	}
}

// WithChatID sets the chat ID.
func WithChatID(chatID int64) Option {
	return func(c *Config) {
		c.ChatID = chatID
	}
}

// WithMaxRetries sets the maximum retry attempts.
func WithMaxRetries(retries int) Option {
	return func(c *Config) {
		c.MaxRetries = retries
	}
}

// WithRateLimit sets the rate limit (requests per second).
func WithRateLimit(rps int) Option {
	return func(c *Config) {
		c.RateLimit = rps
	}
}

// WithHTTPTimeout sets the HTTP request timeout.
func WithHTTPTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.HTTPTimeout = timeout
	}
}

// WithMaxMessageBytes sets the threshold for auto file conversion.
func WithMaxMessageBytes(bytes int) Option {
	return func(c *Config) {
		c.MaxMessageBytes = bytes
	}
}
