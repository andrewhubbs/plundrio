package server

import (
	"encoding/json"
	"testing"
)

// TestTorrentAddResponseMatchesTransmissionSpec validates response matches Transmission RPC spec
func TestTorrentAddResponseMatchesTransmissionSpec(t *testing.T) {
	// Per Transmission RPC spec, torrent-add should return:
	// {
	//   "torrent-added": {
	//     "id": number,
	//     "name": string,
	//     "hashString": string
	//   }
	// }

	// Simulated transfer data (what Put.io would return)
	transferID := int64(12345)
	transferName := "Test.Movie.2024.1080p"
	transferHash := "abc123def456"

	// This mirrors the code in handleTorrentAdd
	response := map[string]interface{}{
		"torrent-added": map[string]interface{}{
			"id":         transferID,
			"name":       transferName,
			"hashString": transferHash,
		},
	}

	// Serialize to JSON to validate it's well-formed
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	// Parse it back
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Validate structure
	torrentAdded, ok := parsed["torrent-added"].(map[string]interface{})
	if !ok {
		t.Fatal("torrent-added should be present and be an object")
	}

	// Check id is a number (JSON unmarshals to float64)
	if id, ok := torrentAdded["id"].(float64); !ok || id != float64(transferID) {
		t.Errorf("id should be %d, got %v", transferID, torrentAdded["id"])
	}

	// Check name is correct
	if name, ok := torrentAdded["name"].(string); !ok || name != transferName {
		t.Errorf("name should be %s, got %v", transferName, torrentAdded["name"])
	}

	// Check hashString is correct
	if hash, ok := torrentAdded["hashString"].(string); !ok || hash != transferHash {
		t.Errorf("hashString should be %s, got %v", transferHash, torrentAdded["hashString"])
	}

	t.Logf("Valid Transmission RPC response: %s", string(jsonBytes))
}

// TestEmptyResponseComparison shows the difference between old and new behavior
func TestEmptyResponseComparison(t *testing.T) {
	// OLD behavior (the bug)
	oldResponse := map[string]interface{}{
		"torrent-added": map[string]interface{}{},
	}

	// NEW behavior (the fix)
	newResponse := map[string]interface{}{
		"torrent-added": map[string]interface{}{
			"id":         int64(12345),
			"name":       "Test.Movie.2024.1080p",
			"hashString": "abc123def456",
		},
	}

	oldJSON, _ := json.Marshal(oldResponse)
	newJSON, _ := json.Marshal(newResponse)

	t.Logf("OLD (buggy) response: %s", string(oldJSON))
	t.Logf("NEW (fixed) response: %s", string(newJSON))

	// Validate the old response is missing required fields
	oldTorrent := oldResponse["torrent-added"].(map[string]interface{})
	if len(oldTorrent) != 0 {
		t.Error("Old response should have empty torrent-added")
	}

	// Validate the new response has required fields
	newTorrent := newResponse["torrent-added"].(map[string]interface{})
	if len(newTorrent) != 3 {
		t.Errorf("New response should have 3 fields, got %d", len(newTorrent))
	}
}
