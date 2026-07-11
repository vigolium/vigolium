package secret_detect

import (
	"strings"
	"testing"
)

func TestIsChunkHashManifestMatch(t *testing.T) {
	// A slice of the real webpack chunk-hash manifest that produced the "Looker
	// Client ID" false positive: every value is a 20-char lowercase-hex content
	// hash sitting in a `name:"<hash>"` map entry, and the word "looker" rides in
	// the surrounding module names so the ruleset's word-proximity rule fires.
	const lookerManifest = `{scene_unused_content:"674ef423da0f4f902e35",` +
		`main_navigation_controller:"ad0442c282c5f443103f",` +
		`looker_module:"a60c99f0cbc1120c2023",` +
		`angular_ui_ace:"ff5a99730e3dda6cecad",` +
		`scene_boards_dataflux:"929dc2d57a1615232d40",` +
		`"looker.dataflux.stores.folder_model":"8b2d330eb01e5f1c4263",` +
		`"looker.dataflux.stores.current_user":"c01fa0008d77f1d4f78c",` +
		`"looker.dataflux.modals.file_breadcrumbs":"d03140ea6d9f22ca4538",` +
		`"looker.dataflux.modals.file_navigator":"8ffafb18cab3d35896df",` +
		`"select_file_modal.scss":"309c8baeb52a90ea8513"}`

	// The actual matched value from Finding #64.
	const lookerHash = "8b2d330eb01e5f1c4263"

	tests := []struct {
		name    string
		body    string
		snippet string
		want    bool
	}{
		{
			name:    "webpack chunk-hash manifest entry is a manifest match",
			body:    lookerManifest,
			snippet: lookerHash,
			want:    true,
		},
		{
			name:    "a different hash in the same manifest is also a match",
			body:    lookerManifest,
			snippet: "c01fa0008d77f1d4f78c",
			want:    true,
		},
		{
			name: "numeric-keyed jsonp chunk map is a manifest match",
			body: `(__webpack_require__.u=function(e){return"static/js/"+` +
				`{12:"0a1b2c3d4e5f60718293",` +
				`34:"112233445566778899aa",` +
				`56:"2233445566778899aabb",` +
				`78:"3344556677889900aabb",` +
				`90:"445566778899aabbccdd",` +
				`11:"5566778899aabbccddee",` +
				`13:"66778899aabbccddeeff",` +
				`15:"778899aabbccddeeff00",` +
				`17:"8899aabbccddeeff0011"}[e]})`,
			snippet: "445566778899aabbccdd",
			want:    true,
		},
		{
			name:    "lone hex credential in a JSON config is NOT a manifest match",
			body:    `{"looker_client_id":"8b2d330eb01e5f1c4263","note":"prod key"}`,
			snippet: lookerHash,
			want:    false,
		},
		{
			name: "a real client id alongside a few unrelated hashes is kept",
			body: `{"client_id":"8b2d330eb01e5f1c4263",` +
				`"etag":"674ef423da0f4f902e35",` +
				`"build":"929dc2d57a1615232d40"}`,
			snippet: lookerHash,
			want:    false, // only 3 distinct same-width hashes — below the threshold
		},
		{
			name:    "value with letters past f is not a content hash (kept)",
			body:    strings.Replace(lookerManifest, lookerHash, "8b2d330ebz1e5f1c4263", 1),
			snippet: "8b2d330ebz1e5f1c4263",
			want:    false,
		},
		{
			name:    "uppercase hex is not a webpack content hash (kept)",
			body:    `"a":"8B2D330EB01E5F1C4263","b":"8B2D330EB01E5F1C4263"`,
			snippet: "8B2D330EB01E5F1C4263",
			want:    false,
		},
		{
			name:    "unquoted token amid a manifest is kept (not a map entry)",
			body:    lookerManifest + " token=" + lookerHash,
			snippet: "deadbeefdeadbeefdead", // not present quoted in the body
			want:    false,
		},
		{
			name:    "snippet shorter than the width band is kept",
			body:    `"a":"0a1b2c3d","b":"1a2b3c4d","c":"2a3b4c5d"`,
			snippet: "0a1b2c3", // 7 chars, below chunkHashMinLen
			want:    false,
		},
		{
			name:    "empty body is kept",
			body:    "",
			snippet: lookerHash,
			want:    false,
		},
		{
			name:    "empty snippet is kept",
			body:    lookerManifest,
			snippet: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsChunkHashManifestMatch([]byte(tt.body), tt.snippet, -1, -1)
			if got != tt.want {
				t.Errorf("IsChunkHashManifestMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCountQuotedHexOfLen(t *testing.T) {
	body := []byte(`"aa11bb22cc33dd44ee55","ff66007711882299aabb",` +
		`"aa11bb22cc33dd44ee55",` + // duplicate — counted once
		`"shortone","00112233445566778899eeff"`) // 8-only "shortone" is not hex; last is 24-wide

	// stopAt = 0 counts every distinct value (no early-stop) so the exact tallies
	// can be asserted.
	if got := countQuotedHexOfLen(body, 20, 0); got != 2 {
		t.Errorf("countQuotedHexOfLen(20) = %d, want 2 (distinct)", got)
	}
	if got := countQuotedHexOfLen(body, 24, 0); got != 1 {
		t.Errorf("countQuotedHexOfLen(24) = %d, want 1", got)
	}
	if got := countQuotedHexOfLen(body, 8, 0); got != 0 {
		t.Errorf("countQuotedHexOfLen(8) = %d, want 0 (\"shortone\" is not hex)", got)
	}
	// stopAt halts as soon as the distinct count reaches the cap.
	if got := countQuotedHexOfLen(body, 20, 1); got != 1 {
		t.Errorf("countQuotedHexOfLen(20, stopAt=1) = %d, want 1 (early stop)", got)
	}
}
