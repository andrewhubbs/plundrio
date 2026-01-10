package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elsbrock/go-putio"
	"github.com/elsbrock/plundrio/internal/log"
)

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
			Int64("folder_id", s.cfg.FolderID).
			Msg("Torrent file uploaded")
	} else {
		// Handle magnet links
		if params.MagnetLink != "" {
			name = params.MagnetLink
		} else if params.Filename != "" && strings.HasPrefix(params.Filename, "magnet:") {
			name = params.Filename
		} else {
			return nil, fmt.Errorf("invalid torrent or magnet link provided")
		}

		// Add magnet link to Put.io
		transfer, err := s.client.AddTransfer(name, s.cfg.FolderID)
		if err != nil {
			return nil, fmt.Errorf("failed to add transfer: %w", err)
		}

		log.Info("rpc").
			Str("operation", "torrent-add").
			Str("type", "magnet").
			Str("name", transfer.Name).
			Str("hash", transfer.Hash).
			Int64("id", transfer.ID).
			Int64("folder_id", s.cfg.FolderID).
			Msg("Magnet link added")

		// Return success response with transfer info for *arr tracking
		return map[string]interface{}{
			"torrent-added": map[string]interface{}{
				"id":         transfer.ID,
				"name":       transfer.Name,
				"hashString": transfer.Hash,
			},
		}, nil
	}

	// Return success response
	return map[string]interface{}{
		"torrent-added": map[string]interface{}{},
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
