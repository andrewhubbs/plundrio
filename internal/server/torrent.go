package server

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/elsbrock/go-putio"
	"github.com/elsbrock/plundrio/internal/log"
)

// extractHashFromMagnet extracts the info hash from a magnet URI
// Magnet format: magnet:?xt=urn:btih:HASH&dn=name&...
func extractHashFromMagnet(magnetURI string) string {
	// Parse the magnet URI
	u, err := url.Parse(magnetURI)
	if err != nil {
		return ""
	}

	// Get the xt parameter (exact topic)
	xt := u.Query().Get("xt")
	if xt == "" {
		return ""
	}

	// Extract hash from urn:btih:HASH format
	// Handle both lowercase and uppercase prefixes
	xt = strings.ToLower(xt)
	if strings.HasPrefix(xt, "urn:btih:") {
		hash := strings.TrimPrefix(xt, "urn:btih:")
		// Hash can be hex (40 chars) or base32 (32 chars)
		if len(hash) == 32 {
			// Base32 encoded, decode to hex
			hash = base32ToHex(hash)
		}
		return strings.ToLower(hash)
	}

	return ""
}

// base32ToHex converts a base32 encoded hash to hex
func base32ToHex(b32 string) string {
	// Standard base32 alphabet (RFC 4648)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b32 = strings.ToUpper(b32)

	var bits uint64
	var bitCount int
	var result []byte

	for _, c := range b32 {
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return ""
		}
		bits = (bits << 5) | uint64(idx)
		bitCount += 5

		for bitCount >= 8 {
			bitCount -= 8
			result = append(result, byte(bits>>bitCount))
			bits &= (1 << bitCount) - 1
		}
	}

	return hex.EncodeToString(result)
}

// extractHashFromTorrent computes the info hash from torrent file data
// The info hash is SHA1 of the bencoded "info" dictionary
func extractHashFromTorrent(data []byte) string {
	// Find the info dictionary in the torrent file
	infoStart, infoEnd := findInfoDict(data)
	if infoStart < 0 || infoEnd < 0 {
		return ""
	}

	// Compute SHA1 of the info dictionary
	hash := sha1.Sum(data[infoStart:infoEnd])
	return hex.EncodeToString(hash[:])
}

// findInfoDict finds the start and end positions of the "info" dictionary
// in bencoded torrent data. Returns -1, -1 if not found.
func findInfoDict(data []byte) (int, int) {
	// Look for "4:infod" - the key "info" followed by a dictionary
	pattern := []byte("4:infod")
	idx := findBytes(data, pattern)
	if idx < 0 {
		return -1, -1
	}

	// The info dict starts at the 'd' after "4:info"
	infoStart := idx + 6 // len("4:info") = 6

	// Parse the dictionary to find its end
	end, ok := skipBencode(data, infoStart)
	if !ok {
		return -1, -1
	}

	return infoStart, end
}

// findBytes finds the first occurrence of pattern in data
func findBytes(data, pattern []byte) int {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// skipBencode skips a bencoded value starting at pos and returns the end position
func skipBencode(data []byte, pos int) (int, bool) {
	if pos >= len(data) {
		return -1, false
	}

	switch data[pos] {
	case 'i': // Integer: i<number>e
		end := pos + 1
		for end < len(data) && data[end] != 'e' {
			end++
		}
		if end >= len(data) {
			return -1, false
		}
		return end + 1, true

	case 'l': // List: l<items>e
		pos++
		for pos < len(data) && data[pos] != 'e' {
			var ok bool
			pos, ok = skipBencode(data, pos)
			if !ok {
				return -1, false
			}
		}
		if pos >= len(data) {
			return -1, false
		}
		return pos + 1, true

	case 'd': // Dictionary: d<key><value>...e
		pos++
		for pos < len(data) && data[pos] != 'e' {
			// Skip key (must be a string)
			var ok bool
			pos, ok = skipBencode(data, pos)
			if !ok {
				return -1, false
			}
			// Skip value
			pos, ok = skipBencode(data, pos)
			if !ok {
				return -1, false
			}
		}
		if pos >= len(data) {
			return -1, false
		}
		return pos + 1, true

	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9': // String: <len>:<data>
		// Parse the length
		lenEnd := pos
		for lenEnd < len(data) && data[lenEnd] != ':' {
			lenEnd++
		}
		if lenEnd >= len(data) {
			return -1, false
		}

		// Parse length as integer
		length := 0
		for i := pos; i < lenEnd; i++ {
			length = length*10 + int(data[i]-'0')
		}

		// Skip past colon and string data
		end := lenEnd + 1 + length
		if end > len(data) {
			return -1, false
		}
		return end, true

	default:
		return -1, false
	}
}

// findTransferByHash finds a transfer by its hash string (case-insensitive)
// Only matches transfers in plundrio's configured folder to prevent accidental
// deletion of content in other folders (e.g., chill.institute)
func (s *Server) findTransferByHash(hash string) (*putio.Transfer, error) {
	transfers, err := s.client.GetTransfers()
	if err != nil {
		return nil, err
	}
	for _, t := range transfers {
		// Case-insensitive hash comparison (Radarr sends uppercase, Put.io stores lowercase)
		// AND verify the transfer belongs to plundrio's folder
		if strings.EqualFold(t.Hash, hash) && t.SaveParentID == s.cfg.FolderID {
			return t, nil
		}
	}
	return nil, fmt.Errorf("transfer not found with hash: %s (in folder %d)", hash, s.cfg.FolderID)
}

// handleTorrentAdd processes torrent-add requests
func (s *Server) handleTorrentAdd(args json.RawMessage) (interface{}, error) {
	var params struct {
		Filename    string `json:"filename"`    // For .torrent files
		MetaInfo    string `json:"metainfo"`    // Base64 encoded .torrent
		MagnetLink  string `json:"magnetLink"`  // Magnet link
		DownloadDir string `json:"downloadDir"` // Ignored, we use Put.io
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	var name string

	// Handle .torrent file upload if metainfo is provided
	if params.MetaInfo != "" {
		// Decode base64 torrent data
		torrentData, err := base64.StdEncoding.DecodeString(params.MetaInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to decode torrent data: %w", err)
		}

		// Extract info hash from torrent data BEFORE uploading
		// This is critical for Radarr/Sonarr tracking
		infoHash := extractHashFromTorrent(torrentData)

		// Upload torrent file to Put.io
		name = params.Filename
		if name == "" {
			name = "unknown.torrent"
		}
		if err := s.client.UploadFile(torrentData, name, s.cfg.FolderID); err != nil {
			return nil, fmt.Errorf("failed to upload torrent: %w", err)
		}

		log.Info("rpc").
			Str("operation", "torrent-add").
			Str("type", "torrent").
			Str("name", name).
			Str("hash", infoHash).
			Int64("folder_id", s.cfg.FolderID).
			Msg("Torrent file uploaded")

		// Return success response with hash for *arr tracking
		return map[string]interface{}{
			"torrent-added": map[string]interface{}{
				"name":       name,
				"hashString": infoHash,
			},
		}, nil
	}

	// Handle magnet links
	if params.MagnetLink != "" {
		name = params.MagnetLink
	} else if params.Filename != "" && strings.HasPrefix(params.Filename, "magnet:") {
		name = params.Filename
	} else {
		return nil, fmt.Errorf("invalid torrent or magnet link provided")
	}

	// Extract hash from magnet URI - this is the reliable source
	// Put.io may return empty hash for cached content
	magnetHash := extractHashFromMagnet(name)

	// Add magnet link to Put.io
	transfer, err := s.client.AddTransfer(name, s.cfg.FolderID)
	if err != nil {
		return nil, fmt.Errorf("failed to add transfer: %w", err)
	}

	// Use hash from magnet URI if put.io returned empty hash
	// This happens when content is already cached on put.io
	responseHash := transfer.Hash
	if responseHash == "" && magnetHash != "" {
		responseHash = magnetHash
		log.Debug("rpc").
			Str("operation", "torrent-add").
			Str("magnet_hash", magnetHash).
			Msg("Using hash extracted from magnet URI (put.io returned empty)")
	}

	log.Info("rpc").
		Str("operation", "torrent-add").
		Str("type", "magnet").
		Str("name", transfer.Name).
		Str("hash", responseHash).
		Int64("id", transfer.ID).
		Int64("folder_id", s.cfg.FolderID).
		Msg("Magnet link added")

	// Return success response with transfer info for *arr tracking
	return map[string]interface{}{
		"torrent-added": map[string]interface{}{
			"id":         transfer.ID,
			"name":       transfer.Name,
			"hashString": responseHash,
		},
	}, nil
}

// handleTorrentGet processes torrent-get requests
func (s *Server) handleTorrentGet(args json.RawMessage) (interface{}, error) {
	var params struct {
		IDs    []string `json:"ids"`
		Fields []string `json:"fields"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	// Log input parameters
	log.Debug("rpc").
		Str("operation", "torrent-get").
		Interface("ids", params.IDs).
		Interface("fields", params.Fields).
		Msg("Processing torrent-get request")

	// Get transfers from the processor, which now keeps track of all transfers
	// including completed ones that have been processed
	processor := s.dlManager.GetTransferProcessor()

	// Check if processor is nil
	if processor == nil {
		log.Error("rpc").
			Str("operation", "torrent-get").
			Msg("Transfer processor is nil")
		return map[string]interface{}{
			"torrents": []map[string]interface{}{},
		}, nil
	}

	// Log processor details
	log.Debug("rpc").
		Str("operation", "torrent-get").
		Msg("Using transfer processor")

	transfers := processor.GetTransfers()

	log.Debug("rpc").
		Str("operation", "torrent-get").
		Int("all_transfers_count", len(transfers)).
		Msg("Retrieved all transfers from processor")

	// Convert Put.io transfers to transmission format
	torrents := make([]map[string]interface{}, 0, len(transfers))
	for _, t := range transfers {
		// Filter by IDs if specified
		if len(params.IDs) > 0 {
			found := false
			for _, id := range params.IDs {
				// Case-insensitive hash comparison (hashes are hex strings)
				if strings.EqualFold(id, t.Hash) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Calculate combined progress
		var percentDone float64
		var status int
		var leftUntilDone int64

		// Check if we have a transfer context (transfer is being processed)
		if ctx, exists := s.dlManager.GetCoordinator().GetTransferContext(t.ID); exists && ctx.TotalFiles > 0 {
			// Get the context data
			totalSize := ctx.TotalSize
			downloadedSize := ctx.DownloadedSize
			totalFiles := ctx.TotalFiles
			completedFiles := ctx.CompletedFiles
			state := ctx.State

			// Calculate total size (Put.io download + local download)
			// If we have size information, use it; otherwise fall back to the transfer size
			totalTransferSize := totalSize
			if totalTransferSize == 0 {
				totalTransferSize = int64(t.Size)
			}

			// The total download task is considered as two parts:
			// 1. Put.io downloading the torrent (50% of the total task)
			// 2. Local downloading from Put.io (50% of the total task)

			// Calculate Put.io progress (0-50%)
			putioProgress := float64(t.PercentDone) / 200.0 // Maps 0-100 to 0-0.5

			// Calculate local download progress (0-50%)
			var localProgress float64
			if totalSize > 0 {
				// If we have size information, use bytes downloaded
				localProgress = float64(downloadedSize) / float64(totalSize) * 0.5 // Maps 0-1 to 0-0.5
			} else if totalFiles > 0 {
				// Fall back to file count if size information is not available
				localProgress = float64(completedFiles) / float64(totalFiles) * 0.5 // Maps 0-1 to 0-0.5
			}

			// Combine the two progress values
			percentDone = putioProgress + localProgress

			// Calculate bytes left until done
			// First, calculate how many bytes are left on Put.io side
			putioLeftBytes := int64(float64(t.Size) * (1.0 - float64(t.PercentDone)/100.0))

			// Then, calculate how many bytes are left on local download side
			localLeftBytes := totalSize - downloadedSize

			// Total bytes left is the sum of both
			leftUntilDone = putioLeftBytes + localLeftBytes

			// Ensure leftUntilDone is never negative
			if leftUntilDone < 0 {
				leftUntilDone = 0
			}

			// Check if the transfer is in the Processed state
			if state == 5 { // TransferLifecycleProcessed = 5
				// For transfers that have been processed locally, show as 100% complete
				percentDone = 1.0 // 100%
				leftUntilDone = 0 // Nothing left to download
				status = 6        // TR_STATUS_SEED (completed/seeding)
			} else if state == 2 { // TransferLifecycleCompleted = 2
				status = s.mapPutioStatus(t.Status)
			} else {
				// If not all files are downloaded, show as downloading
				status = 4 // TR_STATUS_DOWNLOAD
			}

			log.Debug("rpc").
				Str("operation", "torrent-get").
				Int64("id", t.ID).
				Str("name", t.Name).
				Float64("putio_progress", putioProgress*100).
				Float64("local_progress", localProgress*100).
				Float64("combined_progress", percentDone*100).
				Int64("left_until_done", leftUntilDone).
				Msg("Calculated progress for transfer with context")
		} else if t.Status == "COMPLETED" || t.Status == "SEEDING" {
			// For transfers that are completed on put.io but have no corresponding entry in the processor
			// (i.e., already downloaded), show as 100% complete with status "downloaded"
			percentDone = 1.0 // 100%
			leftUntilDone = 0 // Nothing left to download
			status = 6        // TR_STATUS_SEED (completed/seeding)
		} else {
			// For other transfers not being processed, just use put.io progress (0-50%)
			putioProgress := float64(t.PercentDone) / 200.0 // Maps 0-100 to 0-0.5
			percentDone = putioProgress

			// Calculate bytes left on Put.io side only
			leftUntilDone = int64(float64(t.Size) * (1.0 - float64(t.PercentDone)/100.0))

			status = s.mapPutioStatus(t.Status)

			log.Debug("rpc").
				Str("operation", "torrent-get").
				Int64("id", t.ID).
				Str("name", t.Name).
				Float64("putio_progress", putioProgress*100).
				Float64("combined_progress", percentDone*100).
				Int64("left_until_done", leftUntilDone).
				Msg("Calculated progress for transfer without context")
		}

		torrentInfo := map[string]interface{}{
			"id":             t.ID,
			"hashString":     t.Hash,
			"name":           t.Name,
			"eta":            t.EstimatedTime,
			"status":         status,
			"downloadDir":    s.cfg.TargetDir,
			"totalSize":      t.Size,
			"leftUntilDone":  leftUntilDone,
			"uploadedEver":   t.Uploaded,
			"downloadedEver": t.Downloaded,
			"percentDone":    percentDone,
			"rateDownload":   t.DownloadSpeed,
			"rateUpload":     t.UploadSpeed,
			"uploadRatio": func() float64 {
				if t.Size > 0 {
					return float64(t.Uploaded) / float64(t.Size)
				}
				return 0
			}(),
			"error":       t.ErrorMessage != "",
			"errorString": t.ErrorMessage,
		}

		torrents = append(torrents, torrentInfo)

		// Log each torrent being added to the response
		log.Debug("rpc").
			Str("operation", "torrent-get").
			Int64("id", t.ID).
			Str("hash", t.Hash).
			Str("name", t.Name).
			Str("status", t.Status).
			Int("size", t.Size).
			Float64("percent_done", percentDone).
			Msg("Added torrent to response")
	}

	// Log the final count of torrents in the response
	log.Debug("rpc").
		Str("operation", "torrent-get").
		Int("torrents_count", len(torrents)).
		Msg("Returning torrents")

	result := map[string]interface{}{
		"torrents": torrents,
	}

	// Log the final response structure
	resultBytes, _ := json.Marshal(result)
	log.Debug("rpc").
		Str("operation", "torrent-get").
		Str("result", string(resultBytes)).
		Msg("Final result structure")

	return result, nil
}

// handleTorrentRemove processes torrent-remove requests
func (s *Server) handleTorrentRemove(args json.RawMessage) (interface{}, error) {
	var params struct {
		IDs             []string `json:"ids"`
		DeleteLocalData bool     `json:"delete-local-data"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	var lastErr error
	successCount := 0

	for _, hash := range params.IDs {
		transfer, err := s.findTransferByHash(hash)
		if err != nil {
			log.Warn("rpc").
				Str("operation", "torrent-remove").
				Str("hash", hash).
				Err(err).
				Msg("Transfer not found in Put.io - may already be removed")
			// Don't treat "not found" as an error - the transfer might already be gone
			// Continue to try deleting local data if requested
		}

		// Delete local data if requested and transfer name is known
		if params.DeleteLocalData && s.cfg.TargetDir != "" && transfer != nil {
			localPath := filepath.Join(s.cfg.TargetDir, transfer.Name)
			if _, statErr := os.Stat(localPath); statErr == nil {
				if removeErr := os.RemoveAll(localPath); removeErr != nil {
					log.Error("rpc").
						Str("operation", "torrent-remove").
						Str("hash", hash).
						Str("path", localPath).
						Err(removeErr).
						Msg("Failed to delete local data")
					lastErr = removeErr
				} else {
					log.Info("rpc").
						Str("operation", "torrent-remove").
						Str("hash", hash).
						Str("path", localPath).
						Msg("Deleted local data")
				}
			}
		}

		// Skip Put.io deletion if transfer wasn't found
		if transfer == nil {
			continue
		}

		// Delete the files from Put.io
		if transfer.FileID != 0 {
			if err := s.client.DeleteFile(transfer.FileID); err != nil {
				log.Error("rpc").
					Str("operation", "torrent-remove").
					Str("hash", hash).
					Int64("transfer_id", transfer.ID).
					Int64("file_id", transfer.FileID).
					Err(err).
					Msg("Failed to delete transfer files from Put.io")
				lastErr = err
			}
		}

		// Delete the transfer from Put.io
		if err := s.client.DeleteTransfer(transfer.ID); err != nil {
			log.Error("rpc").
				Str("operation", "torrent-remove").
				Str("hash", hash).
				Int64("transfer_id", transfer.ID).
				Err(err).
				Msg("Failed to delete transfer from Put.io")
			lastErr = err
		} else {
			successCount++
			log.Info("rpc").
				Str("operation", "torrent-remove").
				Str("hash", hash).
				Str("name", transfer.Name).
				Int64("transfer_id", transfer.ID).
				Bool("delete_local_data", params.DeleteLocalData).
				Msg("Transfer removed from Put.io")
		}
	}

	// Return success even if some deletions failed - this matches Transmission behavior
	// The important thing is that we attempted the deletions
	if lastErr != nil && successCount == 0 {
		log.Warn("rpc").
			Str("operation", "torrent-remove").
			Int("requested", len(params.IDs)).
			Int("succeeded", successCount).
			Err(lastErr).
			Msg("Some removals failed")
	}

	return struct{}{}, nil
}
