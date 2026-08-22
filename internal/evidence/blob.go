package evidence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var ErrBlobNotFound = errors.New("evidence blob not found")

type BlobInfo struct {
	Bucket    string
	Key       string
	VersionID string
	ETag      string
	Size      int64
	Metadata  map[string]string
}

type BlobStore interface {
	Bucket() string
	Put(context.Context, string, io.Reader, int64, string, map[string]string, time.Time) (BlobInfo, error)
	Stat(context.Context, string, string) (BlobInfo, error)
	Open(context.Context, string, string) (io.ReadCloser, BlobInfo, error)
	Health(context.Context) error
}

type MinIOConfig struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	Region    string
	Secure    bool
}

type MinIOBlob struct {
	client *minio.Client
	bucket string
}

func OpenMinIOBlob(ctx context.Context, config MinIOConfig) (*MinIOBlob, error) {
	config.Endpoint = strings.TrimSpace(config.Endpoint)
	config.AccessKey = strings.TrimSpace(config.AccessKey)
	config.SecretKey = strings.TrimSpace(config.SecretKey)
	config.Bucket = strings.TrimSpace(config.Bucket)
	config.Region = strings.TrimSpace(config.Region)
	if config.Endpoint == "" || config.AccessKey == "" || config.SecretKey == "" || config.Bucket == "" {
		return nil, errors.New("MinIO endpoint, credentials and evidence bucket are required")
	}
	client, err := minio.New(config.Endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(config.AccessKey, config.SecretKey, ""), Secure: config.Secure, Region: config.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("create MinIO client: %w", err)
	}
	exists, err := client.BucketExists(ctx, config.Bucket)
	if err != nil {
		return nil, fmt.Errorf("check evidence bucket: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, config.Bucket, minio.MakeBucketOptions{Region: config.Region, ObjectLocking: true}); err != nil {
			return nil, fmt.Errorf("create object-locked evidence bucket: %w", err)
		}
	}
	objectLock, _, _, _, err := client.GetObjectLockConfig(ctx, config.Bucket)
	if err != nil {
		return nil, fmt.Errorf("read evidence object-lock configuration: %w", err)
	}
	if !strings.EqualFold(objectLock, "Enabled") {
		return nil, errors.New("evidence bucket must have object locking enabled")
	}
	if err := client.SetBucketVersioning(ctx, config.Bucket, minio.BucketVersioningConfiguration{Status: "Enabled"}); err != nil {
		return nil, fmt.Errorf("enable evidence bucket versioning: %w", err)
	}
	return &MinIOBlob{client: client, bucket: config.Bucket}, nil
}

func (m *MinIOBlob) Bucket() string { return m.bucket }

func (m *MinIOBlob) Health(ctx context.Context) error {
	exists, err := m.client.BucketExists(ctx, m.bucket)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("evidence bucket is unavailable")
	}
	return nil
}

func (m *MinIOBlob) Put(ctx context.Context, key string, reader io.Reader, size int64, contentType string, metadata map[string]string, retainUntil time.Time) (BlobInfo, error) {
	if !retainUntil.After(time.Now().UTC()) {
		return BlobInfo{}, errors.New("evidence retention deadline must be in the future")
	}
	info, err := m.client.PutObject(ctx, m.bucket, key, reader, size, minio.PutObjectOptions{
		ContentType: contentType, UserMetadata: metadata, Mode: minio.Compliance, RetainUntilDate: retainUntil.UTC(),
	})
	if err != nil {
		return BlobInfo{}, fmt.Errorf("put immutable evidence object: %w", err)
	}
	return BlobInfo{Bucket: info.Bucket, Key: info.Key, VersionID: info.VersionID, ETag: info.ETag, Size: info.Size, Metadata: metadata}, nil
}

func (m *MinIOBlob) Stat(ctx context.Context, key, versionID string) (BlobInfo, error) {
	info, err := m.client.StatObject(ctx, m.bucket, key, minio.StatObjectOptions{VersionID: versionID})
	if err != nil {
		response := minio.ToErrorResponse(err)
		if response.StatusCode == 404 || response.Code == "NoSuchKey" || response.Code == "NoSuchVersion" {
			return BlobInfo{}, ErrBlobNotFound
		}
		return BlobInfo{}, fmt.Errorf("stat evidence object: %w", err)
	}
	metadata := map[string]string{}
	for key, value := range info.UserMetadata {
		metadata[strings.ToLower(key)] = value
	}
	return BlobInfo{Bucket: m.bucket, Key: info.Key, VersionID: info.VersionID, ETag: info.ETag, Size: info.Size, Metadata: metadata}, nil
}

func (m *MinIOBlob) Open(ctx context.Context, key, versionID string) (io.ReadCloser, BlobInfo, error) {
	info, err := m.Stat(ctx, key, versionID)
	if err != nil {
		return nil, BlobInfo{}, err
	}
	object, err := m.client.GetObject(ctx, m.bucket, key, minio.GetObjectOptions{VersionID: versionID, Checksum: true})
	if err != nil {
		return nil, BlobInfo{}, fmt.Errorf("open evidence object: %w", err)
	}
	return object, info, nil
}
