package dr

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

type objectStores struct {
	cfg    Config
	source *minio.Client
	target *minio.Client
}

func newObjectStores(cfg Config) (*objectStores, error) {
	source, err := minio.New(cfg.SourceEndpoint.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.SourceAccessKey, cfg.SourceSecretKey, ""),
		Secure: cfg.SourceEndpoint.Secure,
		Region: cfg.SourceRegion,
	})
	if err != nil {
		return nil, fmt.Errorf("configure source object store: %w", err)
	}
	target, err := minio.New(cfg.TargetEndpoint.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.TargetAccessKey, cfg.TargetSecretKey, ""),
		Secure: cfg.TargetEndpoint.Secure,
		Region: cfg.TargetRegion,
	})
	if err != nil {
		return nil, fmt.Errorf("configure backup object store: %w", err)
	}
	return &objectStores{cfg: cfg, source: source, target: target}, nil
}

func (s *objectStores) prepare(ctx context.Context) error {
	sourceExists, err := s.source.BucketExists(ctx, s.cfg.SourceBucket)
	if err != nil {
		return fmt.Errorf("inspect source bucket: %w", err)
	}
	if !sourceExists {
		return fmt.Errorf("source bucket %s does not exist", s.cfg.SourceBucket)
	}
	targetExists, err := s.target.BucketExists(ctx, s.cfg.TargetBucket)
	if err != nil {
		return fmt.Errorf("inspect backup bucket: %w", err)
	}
	if !targetExists {
		if err := s.target.MakeBucket(ctx, s.cfg.TargetBucket, minio.MakeBucketOptions{Region: s.cfg.TargetRegion}); err != nil {
			return fmt.Errorf("create backup bucket: %w", err)
		}
	}
	return nil
}

func (s *objectStores) backupObjects(ctx context.Context, prefix, inventoryPath string) (int64, int64, error) {
	inventory, err := os.OpenFile(inventoryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, 0, err
	}
	encoder := json.NewEncoder(inventory)
	var count, bytesStored int64
	for object := range s.source.ListObjects(ctx, s.cfg.SourceBucket, minio.ListObjectsOptions{Recursive: true}) {
		if object.Err != nil {
			_ = inventory.Close()
			return count, bytesStored, fmt.Errorf("list source objects: %w", object.Err)
		}
		source, err := s.source.GetObject(ctx, s.cfg.SourceBucket, object.Key, minio.GetObjectOptions{VersionID: object.VersionID})
		if err != nil {
			_ = inventory.Close()
			return count, bytesStored, fmt.Errorf("open source object %q: %w", object.Key, err)
		}
		info, err := source.Stat()
		if err != nil {
			_ = source.Close()
			_ = inventory.Close()
			return count, bytesStored, fmt.Errorf("stat source object %q: %w", object.Key, err)
		}
		hash := sha256.New()
		destinationKey := prefix + "/minio/" + s.cfg.SourceBucket + "/" + strings.TrimPrefix(object.Key, "/")
		uploaded, err := s.target.PutObject(ctx, s.cfg.TargetBucket, destinationKey, io.TeeReader(source, hash), info.Size, minio.PutObjectOptions{
			ContentType:  info.ContentType,
			UserMetadata: info.UserMetadata,
		})
		closeErr := source.Close()
		if err != nil {
			_ = inventory.Close()
			return count, bytesStored, fmt.Errorf("backup source object %q: %w", object.Key, err)
		}
		if closeErr != nil {
			_ = inventory.Close()
			return count, bytesStored, closeErr
		}
		record := ObjectRecord{
			Key: object.Key, Size: info.Size, SHA256: hex.EncodeToString(hash.Sum(nil)),
			ETag: info.ETag, VersionID: info.VersionID, LastModified: info.LastModified.UTC(),
			ContentType: info.ContentType, Metadata: info.UserMetadata,
		}
		if uploaded.Size != info.Size {
			_ = inventory.Close()
			return count, bytesStored, fmt.Errorf("backup object %q size mismatch", object.Key)
		}
		if err := encoder.Encode(record); err != nil {
			_ = inventory.Close()
			return count, bytesStored, err
		}
		count++
		bytesStored += info.Size
	}
	if err := inventory.Close(); err != nil {
		return count, bytesStored, err
	}
	return count, bytesStored, nil
}

func (s *objectStores) restoreObjects(ctx context.Context, prefix, inventoryPath, destinationBucket string) (count int64, bytesRestored int64, retErr error) {
	exists, err := s.source.BucketExists(ctx, destinationBucket)
	if err != nil {
		return 0, 0, err
	}
	if exists {
		return 0, 0, fmt.Errorf("restore bucket %s already exists", destinationBucket)
	}
	if err := s.source.MakeBucket(ctx, destinationBucket, minio.MakeBucketOptions{Region: s.cfg.SourceRegion}); err != nil {
		return 0, 0, fmt.Errorf("create restore bucket: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = s.removeSourceBucket(context.Background(), destinationBucket)
		}
	}()
	inventory, err := os.Open(inventoryPath)
	if err != nil {
		return 0, 0, err
	}
	defer inventory.Close()
	decoder := json.NewDecoder(bufio.NewReader(inventory))
	for {
		var record ObjectRecord
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return count, bytesRestored, fmt.Errorf("decode object inventory: %w", err)
		}
		if record.Key == "" || record.Size < 0 || len(record.SHA256) != sha256.Size*2 {
			return count, bytesRestored, errors.New("object inventory contains an invalid record")
		}
		backupKey := prefix + "/minio/" + s.cfg.SourceBucket + "/" + strings.TrimPrefix(record.Key, "/")
		source, err := s.target.GetObject(ctx, s.cfg.TargetBucket, backupKey, minio.GetObjectOptions{})
		if err != nil {
			return count, bytesRestored, fmt.Errorf("open backed-up object %q: %w", record.Key, err)
		}
		hash := sha256.New()
		uploaded, err := s.source.PutObject(ctx, destinationBucket, record.Key, io.TeeReader(source, hash), record.Size, minio.PutObjectOptions{
			ContentType:  record.ContentType,
			UserMetadata: record.Metadata,
		})
		closeErr := source.Close()
		if err != nil {
			return count, bytesRestored, fmt.Errorf("restore object %q: %w", record.Key, err)
		}
		if closeErr != nil {
			return count, bytesRestored, closeErr
		}
		actual := hex.EncodeToString(hash.Sum(nil))
		if actual != record.SHA256 || uploaded.Size != record.Size {
			return count, bytesRestored, fmt.Errorf("restored object %q failed SHA-256 verification", record.Key)
		}
		count++
		bytesRestored += record.Size
	}
	success = true
	return count, bytesRestored, nil
}

func (s *objectStores) putFile(ctx context.Context, key, filename string, artifact Artifact) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	uploaded, err := s.target.PutObject(ctx, s.cfg.TargetBucket, key, file, artifact.Size, minio.PutObjectOptions{
		ContentType:  "application/octet-stream",
		UserMetadata: map[string]string{"sha256": artifact.SHA256, "kcsp-artifact-kind": artifact.Kind},
	})
	if err != nil {
		return err
	}
	if uploaded.Size != artifact.Size {
		return fmt.Errorf("uploaded artifact %q size mismatch", artifact.Path)
	}
	return nil
}

func (s *objectStores) putBytes(ctx context.Context, key, contentType string, value []byte) error {
	_, err := s.target.PutObject(ctx, s.cfg.TargetBucket, key, strings.NewReader(string(value)), int64(len(value)), minio.PutObjectOptions{ContentType: contentType})
	return err
}

func (s *objectStores) getBytes(ctx context.Context, key string, maximum int64) ([]byte, error) {
	object, err := s.target.GetObject(ctx, s.cfg.TargetBucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer object.Close()
	info, err := object.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size > maximum {
		return nil, fmt.Errorf("object %q exceeds maximum size", key)
	}
	value, err := io.ReadAll(io.LimitReader(object, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) != info.Size {
		return nil, fmt.Errorf("object %q was truncated", key)
	}
	return value, nil
}

func (s *objectStores) getFile(ctx context.Context, key, filename string, artifact Artifact) error {
	object, err := s.target.GetObject(ctx, s.cfg.TargetBucket, key, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	defer object.Close()
	if err := os.MkdirAll(filepathDir(filename), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(object, artifact.Size+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if size != artifact.Size || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return fmt.Errorf("artifact %q failed SHA-256 verification", artifact.Path)
	}
	return nil
}

func (s *objectStores) objectExists(ctx context.Context, key string) (bool, error) {
	_, err := s.target.StatObject(ctx, s.cfg.TargetBucket, key, minio.StatObjectOptions{})
	if err == nil {
		return true, nil
	}
	response := minio.ToErrorResponse(err)
	if response.Code == "NoSuchKey" || response.Code == "NoSuchObject" || response.StatusCode == 404 {
		return false, nil
	}
	return false, err
}

func (s *objectStores) snapshotIDs(ctx context.Context) ([]string, error) {
	var ids []string
	for object := range s.target.ListObjects(ctx, s.cfg.TargetBucket, minio.ListObjectsOptions{Prefix: "snapshots/", Recursive: false}) {
		if object.Err != nil {
			return nil, object.Err
		}
		value := strings.TrimSuffix(strings.TrimPrefix(object.Key, "snapshots/"), "/")
		if !backupIDPattern.MatchString(value) {
			continue
		}
		complete, err := s.objectExists(ctx, "snapshots/"+value+"/_SUCCESS")
		if err != nil {
			return nil, err
		}
		if complete {
			ids = append(ids, value)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return backupEpoch(ids[i]) > backupEpoch(ids[j]) })
	return ids, nil
}

func (s *objectStores) removePrefix(ctx context.Context, prefix string) error {
	for object := range s.target.ListObjects(ctx, s.cfg.TargetBucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if object.Err != nil {
			return object.Err
		}
		if err := s.target.RemoveObject(ctx, s.cfg.TargetBucket, object.Key, minio.RemoveObjectOptions{}); err != nil {
			return err
		}
	}
	return nil
}

func (s *objectStores) removeSourceBucket(ctx context.Context, bucket string) error {
	for object := range s.source.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true}) {
		if object.Err != nil {
			return object.Err
		}
		if err := s.source.RemoveObject(ctx, bucket, object.Key, minio.RemoveObjectOptions{}); err != nil {
			return err
		}
	}
	return s.source.RemoveBucket(ctx, bucket)
}

func (s *objectStores) verifySourceObject(ctx context.Context, bucket, key, expected string) error {
	object, err := s.source.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	defer object.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, object); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fmt.Errorf("evidence object %q SHA-256 mismatch", key)
	}
	return nil
}

func backupEpoch(id string) int64 {
	value := strings.SplitN(id, "-", 2)[0]
	epoch, _ := strconv.ParseInt(value, 10, 64)
	return epoch
}

func filepathDir(filename string) string {
	index := strings.LastIndexAny(filename, "/\\")
	if index < 0 {
		return "."
	}
	return filename[:index]
}
