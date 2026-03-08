package config

// NotifyConfig holds notification configuration
type NotifyConfig struct {
	Enabled    bool           `yaml:"enabled"`
	Severities []string       `yaml:"severities"`
	Telegram   TelegramConfig `yaml:"telegram"`
	Discord    DiscordConfig  `yaml:"discord"`
}

// TelegramConfig holds Telegram notification settings
type TelegramConfig struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

// DiscordConfig holds Discord notification settings
type DiscordConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

// DefaultNotifyConfig returns default notification configuration (disabled)
func DefaultNotifyConfig() *NotifyConfig {
	return &NotifyConfig{
		Enabled:    false,
		Severities: []string{"high", "critical", "medium"},
	}
}
