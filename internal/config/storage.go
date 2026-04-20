package config

import "fmt"

// StorageConfig holds cloud object storage settings for source upload/download
// and scan result archival. Uses minio-go (S3-compatible) for all providers.
type StorageConfig struct {
	Enabled   *bool  `yaml:"enabled,omitempty"`    // default: false
	Driver    string `yaml:"driver,omitempty"`      // gcs (default), s3, minio
	Endpoint  string `yaml:"endpoint,omitempty"`    // auto-detected for gcs/s3; required for minio
	Bucket    string `yaml:"bucket,omitempty"`      // bucket name
	Region    string `yaml:"region,omitempty"`      // bucket region (e.g. us-central1, us-east-1)
	AccessKey string `yaml:"access_key,omitempty"`  // S3 access key / GCS HMAC key
	SecretKey string `yaml:"secret_key,omitempty"`  // S3 secret key / GCS HMAC secret
	UseSSL    *bool  `yaml:"use_ssl,omitempty"`     // default: true
	PathStyle *bool  `yaml:"path_style,omitempty"`  // force path-style addressing (for minio); default: false
}

// IsEnabled returns whether cloud storage is enabled. Defaults to false.
func (c *StorageConfig) IsEnabled() bool {
	return c.Enabled != nil && *c.Enabled
}

// EffectiveDriver returns the storage driver, defaulting to "gcs".
func (c *StorageConfig) EffectiveDriver() string {
	switch c.Driver {
	case "s3":
		return "s3"
	case "minio":
		return "minio"
	default:
		return "gcs"
	}
}

// EffectiveEndpoint returns the endpoint for the configured driver.
// GCS uses storage.googleapis.com, S3 uses s3.amazonaws.com, minio requires explicit config.
func (c *StorageConfig) EffectiveEndpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	switch c.EffectiveDriver() {
	case "gcs":
		return "storage.googleapis.com"
	case "s3":
		return "s3.amazonaws.com"
	default:
		return ""
	}
}

// EffectiveUseSSL returns whether to use HTTPS. Defaults to true.
func (c *StorageConfig) EffectiveUseSSL() bool {
	if c.UseSSL == nil {
		return true
	}
	return *c.UseSSL
}

// EffectivePathStyle returns whether to use path-style addressing. Defaults to false.
func (c *StorageConfig) EffectivePathStyle() bool {
	if c.PathStyle == nil {
		return false
	}
	return *c.PathStyle
}

// Validate checks that StorageConfig fields are valid when enabled.
func (c *StorageConfig) Validate() error {
	if !c.IsEnabled() {
		return nil
	}
	if c.Bucket == "" {
		return fmt.Errorf("storage.bucket must not be empty when storage is enabled")
	}
	if c.AccessKey == "" {
		return fmt.Errorf("storage.access_key must not be empty when storage is enabled")
	}
	if c.SecretKey == "" {
		return fmt.Errorf("storage.secret_key must not be empty when storage is enabled")
	}
	if c.EffectiveDriver() == "minio" && c.Endpoint == "" {
		return fmt.Errorf("storage.endpoint is required when driver is minio")
	}
	return nil
}

// DefaultStorageConfig returns sensible defaults (disabled, GCS driver).
func DefaultStorageConfig() *StorageConfig {
	return &StorageConfig{
		Driver: "gcs",
		Region: "asia-southeast1",
	}
}
