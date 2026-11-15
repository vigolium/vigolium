package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseHostFilter(t *testing.T) {
	for in, want := range map[string]HostFilter{
		"api.shop.local":            {Host: "api.shop.local"},
		"127.0.0.1:18941":           {Host: "127.0.0.1", Port: 18941},
		"https://api.shop.local":    {Host: "api.shop.local", Port: 443, Scheme: "https"},
		"http://example.com:8080/x": {Host: "example.com", Port: 8080, Scheme: "http"},
		"[::1]:8080":                {Host: "::1", Port: 8080},
		"[::1]":                     {Host: "::1"},
		"::1":                       {Host: "::1"},
		"*.example.com":             {Host: "*.example.com"},
		"":                          {},
	} {
		require.Equal(t, want, ParseHostFilter(in), in)
	}
}

// The host a traffic row prints filters back to that row.
func TestRecordQueryAcceptsOriginHost(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	for i, r := range []struct {
		scheme, host string
		port         int
	}{{"https", "api.shop.local", 443}, {"http", "127.0.0.1", 18941}, {"http", "api.shop.local", 80}} {
		_, err := db.NewInsert().Model(&HTTPRecord{
			UUID: "rec-" + string(rune('a'+i)), Scheme: r.scheme, Hostname: r.host, Port: r.port,
			Method: "GET", Path: "/", URL: r.scheme + "://" + r.host + "/", HTTPVersion: "HTTP/1.1",
			RequestHash: "h" + string(rune('a'+i)),
		}).Exec(ctx)
		require.NoError(t, err)
	}
	count := func(host string) int {
		recs, err := NewQueryBuilder(db, QueryFilters{HostPattern: host}).Execute(ctx)
		require.NoError(t, err)
		return len(recs)
	}
	require.Equal(t, 1, count("https://api.shop.local"))
	require.Equal(t, 2, count("api.shop.local"))
	require.Equal(t, 1, count("127.0.0.1:18941"))
	require.Equal(t, 1, count("http://127.0.0.1:18941"))
	require.Equal(t, 0, count("https://example.com"))
}
