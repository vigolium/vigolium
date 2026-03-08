package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OpenAIClient calls any OpenAI-compatible chat completions endpoint.
type OpenAIClient struct {
	apiKey      string
	model       string
	baseURL     string
	maxTokens   int
	temperature float64
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponseFormat struct {
	Type string `json:"type"` // "json_object" or "text"
}

type openaiRequest struct {
	Model          string               `json:"model"`
	Messages       []openaiMessage      `json:"messages"`
	MaxTokens      int                  `json:"max_tokens,omitempty"`
	Temperature    float64              `json:"temperature,omitempty"`
	ResponseFormat *openaiResponseFormat `json:"response_format,omitempty"`
}

type openaiResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// Complete sends a completion request to an OpenAI-compatible endpoint.
func (c *OpenAIClient) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	model := c.model
	if req.Model != "" {
		model = req.Model
	}
	maxTokens := c.maxTokens
	if req.MaxTokens > 0 {
		maxTokens = req.MaxTokens
	}
	temperature := c.temperature
	if req.Temperature != 0 {
		temperature = req.Temperature
	}

	var msgs []openaiMessage
	for _, m := range req.Messages {
		msgs = append(msgs, openaiMessage(m))
	}

	// Append JSON schema instructions to system message (or add new one).
	if req.JSONSchema != "" {
		instruction := "Respond with valid JSON matching this schema. Output ONLY the JSON object, no commentary:\n" + req.JSONSchema
		if len(msgs) > 0 && msgs[0].Role == "system" {
			msgs[0].Content += "\n\n" + instruction
		} else {
			msgs = append([]openaiMessage{{Role: "system", Content: instruction}}, msgs...)
		}
	}

	payload := openaiRequest{
		Model:       model,
		Messages:    msgs,
		MaxTokens:   maxTokens,
		Temperature: temperature,
	}
	if req.JSONSchema != "" {
		payload.ResponseFormat = &openaiResponseFormat{Type: "json_object"}
	}

	return callOpenAIURL(ctx, c.apiKey, c.baseURL+"/chat/completions", payload)
}

// callOpenAIURL is the internal HTTP call, extracted for testability.
func callOpenAIURL(ctx context.Context, apiKey, url string, payload openaiRequest) (*CompletionResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("openai: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("openai: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai: http request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("openai: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	var or openaiResponse
	if err := json.Unmarshal(respBody, &or); err != nil {
		return nil, fmt.Errorf("openai: decode response: %w", err)
	}
	if or.Error != nil {
		return nil, fmt.Errorf("openai error %s: %s", or.Error.Type, or.Error.Message)
	}
	if len(or.Choices) == 0 {
		return nil, fmt.Errorf("openai: empty choices in response")
	}

	return &CompletionResponse{
		Content:   or.Choices[0].Message.Content,
		Model:     or.Model,
		TokensIn:  or.Usage.PromptTokens,
		TokensOut: or.Usage.CompletionTokens,
	}, nil
}
