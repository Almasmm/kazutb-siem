package ingest

import "time"

const (
	MaxBatchEvents       = 500
	MaxBatchRequestBytes = 16 << 20
)

type RawBatchItem struct {
	Format         string    `json:"format"`
	ContentType    string    `json:"content_type,omitempty"`
	EventID        string    `json:"event_id,omitempty"`
	EventTimestamp time.Time `json:"event_timestamp,omitempty"`
	SourceID       string    `json:"source_id,omitempty"`
	SourceAddress  string    `json:"source_address,omitempty"`
	Payload        []byte    `json:"payload"`
}

type RawBatchRequest struct {
	Items []RawBatchItem `json:"items"`
}

type RawBatchReceipt struct {
	Receipts []Receipt `json:"receipts"`
}
