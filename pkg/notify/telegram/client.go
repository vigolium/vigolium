package telegram

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/ratelimit"
	stringsutil "github.com/projectdiscovery/utils/strings"
	tele "gopkg.in/telebot.v3"
)

// Client is a Telegram notification client.
type Client struct {
	config      *Config
	bot         *tele.Bot
	rateLimiter *ratelimit.Limiter
}

// NewClient creates a new Telegram Client with the given options.
// It automatically loads configuration from environment variables if not provided.
func NewClient(opts ...Option) (*Client, error) {
	config := DefaultConfig()

	// Apply functional options
	for _, opt := range opts {
		opt(config)
	}

	// Load from environment for any unset values
	if err := config.LoadFromEnv(); err != nil {
		return nil, errors.Wrap(err, "failed to load config from environment")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid configuration")
	}

	// Create telebot instance
	botSettings := tele.Settings{
		Token:     config.BotToken,
		ParseMode: tele.ModeMarkdownV2,
		Client: &http.Client{
			Timeout: config.HTTPTimeout,
		},
	}

	bot, err := tele.NewBot(botSettings)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create telegram bot")
	}

	// Create rate limiter
	limiter := ratelimit.New(
		context.Background(),
		uint(config.RateLimit),
		time.Second,
	)

	return &Client{
		config:      config,
		bot:         bot,
		rateLimiter: limiter,
	}, nil
}

// Send sends a text message to the configured chat.
// If the message exceeds MaxMessageBytes, it automatically sends as a file.
func (c *Client) Send(msg string) error {
	if msg == "" {
		return nil
	}

	// Check if message exceeds limit, auto-convert to file
	if len([]byte(msg)) > c.config.MaxMessageBytes {
		return c.SendStringAsFile(msg, "message.txt")
	}

	return c.sendText(msg)
}

// SendWithFilename sends a text message, falling back to file with custom filename
// if the message exceeds MaxMessageBytes.
func (c *Client) SendWithFilename(msg string, filename string) error {
	if msg == "" {
		return nil
	}

	if len([]byte(msg)) > c.config.MaxMessageBytes {
		return c.SendStringAsFile(msg, filename)
	}

	return c.sendText(msg)
}

// sendText sends a text message, splitting if necessary.
func (c *Client) sendText(msg string) error {
	msgParts := splitMessage(msg, c.config.MaxMessageBytes)

	for _, msgPart := range msgParts {
		if err := c.sendSingleMessage(msgPart); err != nil {
			return err
		}
	}

	return nil
}

// sendSingleMessage sends a single text message with retry logic.
func (c *Client) sendSingleMessage(msg string) error {
	c.rateLimiter.Take()

	for i := 0; i < c.config.MaxRetries; i++ {
		_, err := c.bot.Send(
			&tele.Chat{ID: c.config.ChatID},
			msg,
			&tele.SendOptions{
				ParseMode: tele.ModeMarkdownV2,
			},
		)

		if err == nil {
			return nil
		}

		if stringsutil.ContainsAny(err.Error(), "Too Many Requests", "retry after") {
			sleepDuration := time.Duration(math.Min(float64(i+1), 10)) * time.Second
			time.Sleep(sleepDuration)
			continue
		}

		return errors.Wrap(err, "failed to send message")
	}

	return errors.New("failed to send message after max retries")
}

// SendFile sends a file from disk to the configured chat.
func (c *Client) SendFile(filePath string) error {
	return c.SendFileWithCaption(filePath, "")
}

// SendFileWithCaption sends a file from disk with a caption.
func (c *Client) SendFileWithCaption(filePath string, caption string) error {
	if filePath == "" {
		return errors.New("file path cannot be empty")
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return errors.Wrapf(err, "unable to access file at %s", filePath)
	}

	if fileInfo.Size() == 0 {
		return errors.New("file is empty")
	}

	c.rateLimiter.Take()

	for i := 0; i < c.config.MaxRetries; i++ {
		_, err := c.bot.Send(
			&tele.Chat{ID: c.config.ChatID},
			&tele.Document{
				File:     tele.FromDisk(filePath),
				FileName: fileInfo.Name(),
				Caption:  caption,
			},
			&tele.SendOptions{
				ParseMode: tele.ModeMarkdownV2,
			},
		)

		if err == nil {
			return nil
		}

		if stringsutil.ContainsAny(err.Error(), "Too Many Requests", "retry after") {
			sleepDuration := time.Duration(math.Min(float64(i+1), 10)) * time.Second
			time.Sleep(sleepDuration)
			continue
		}

		return errors.Wrap(err, "failed to send file")
	}

	return errors.New("failed to send file after max retries")
}

// SendStringAsFile sends a string as a file attachment.
// If the file is too large for Telegram, it automatically compresses with gzip.
func (c *Client) SendStringAsFile(content string, filename string) error {
	if content == "" {
		return nil
	}

	return c.sendReaderAsFileWithCaption(strings.NewReader(content), filename, "")
}

// SendStringAsFileWithCaption sends a string as a file with a caption.
func (c *Client) SendStringAsFileWithCaption(content string, filename string, caption string) error {
	if content == "" {
		return nil
	}

	return c.sendReaderAsFileWithCaption(strings.NewReader(content), filename, caption)
}

// SendBytesAsFile sends byte content as a file attachment.
func (c *Client) SendBytesAsFile(content []byte, filename string) error {
	if len(content) == 0 {
		return nil
	}

	return c.sendReaderAsFileWithCaption(bytes.NewReader(content), filename, "")
}

// SendReaderAsFile sends content from an io.Reader as a file attachment.
func (c *Client) SendReaderAsFile(reader io.Reader, filename string) error {
	return c.sendReaderAsFileWithCaption(reader, filename, "")
}

// sendReaderAsFileWithCaption is the core implementation for sending reader content as file.
func (c *Client) sendReaderAsFileWithCaption(reader io.Reader, filename string, caption string) error {
	c.rateLimiter.Take()

	// Read all content first (needed for potential gzip retry)
	content, err := io.ReadAll(reader)
	if err != nil {
		return errors.Wrap(err, "failed to read content")
	}

	sendFile := func(r io.Reader, fname string) error {
		for i := 0; i < c.config.MaxRetries; i++ {
			_, err := c.bot.Send(
				&tele.Chat{ID: c.config.ChatID},
				&tele.Document{
					File:     tele.FromReader(r),
					FileName: fname,
					Caption:  caption,
				},
				&tele.SendOptions{
					ParseMode: tele.ModeMarkdownV2,
				},
			)

			if err == nil {
				return nil
			}

			if stringsutil.ContainsAny(err.Error(), "Too Many Requests", "retry after") {
				sleepDuration := time.Duration(math.Min(float64(i+1), 10)) * time.Second
				time.Sleep(sleepDuration)
				continue
			}

			if strings.Contains(err.Error(), "Request Entity Too Large") {
				return err // Return immediately to trigger gzip
			}

			return errors.Wrap(err, "failed to send file")
		}
		return errors.New("failed to send file after max retries")
	}

	// Try sending as plain content first
	err = sendFile(bytes.NewReader(content), filename)
	if err != nil && (strings.Contains(err.Error(), "Request Entity Too Large") || err == tele.ErrTooLarge) {
		// Compress with gzip and retry
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(content); err != nil {
			return errors.Wrap(err, "failed to gzip content")
		}
		if err := gz.Close(); err != nil {
			return errors.Wrap(err, "failed to close gzip writer")
		}

		return sendFile(&buf, filename+".gz")
	}

	return err
}

// Close releases resources used by the client.
func (c *Client) Close() {
	if c.rateLimiter != nil {
		c.rateLimiter.Stop()
	}
}
