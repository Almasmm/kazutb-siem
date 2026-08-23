package dr

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var configurationPaths = []string{
	"content",
	"api",
	"internal/store/migrations",
	"internal/store/clickhouse_migrations",
	"observability",
	"compose.yaml",
	".env.example",
}

func archiveConfiguration(root, destination string) error {
	root = filepath.Clean(root)
	configurationRoot, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer configurationRoot.Close()
	// #nosec G304 -- destination is generated beneath the validated absolute private DR work directory.
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(destination)
		}
	}()
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, relativeRoot := range configurationPaths {
		absoluteRoot := filepath.Join(root, filepath.FromSlash(relativeRoot))
		if _, err := os.Lstat(absoluteRoot); err != nil {
			return fmt.Errorf("required configuration path %s: %w", relativeRoot, err)
		}
		err := filepath.Walk(absoluteRoot, func(current string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.Mode()&os.ModeSymlink != 0 || (!info.Mode().IsRegular() && !info.IsDir()) {
				return fmt.Errorf("configuration archive refuses non-regular path %s", current)
			}
			relative, err := filepath.Rel(root, current)
			if err != nil {
				return err
			}
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(relative)
			header.ModTime = time.Unix(0, 0).UTC()
			header.AccessTime = time.Time{}
			header.ChangeTime = time.Time{}
			header.Uid = 0
			header.Gid = 0
			header.Uname = ""
			header.Gname = ""
			if info.IsDir() {
				header.Mode = 0o750
			} else {
				header.Mode = 0o640
			}
			if err := tarWriter.WriteHeader(header); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			source, err := configurationRoot.Open(relative)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tarWriter, source)
			closeErr := source.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		})
		if err != nil {
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	success = true
	return nil
}

func extractConfiguration(archivePath, destination string) error {
	// #nosec G304 -- archivePath is an HMAC-manifested artifact verified by size and SHA-256 before extraction.
	source, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer source.Close()
	gzipReader, err := gzip.NewReader(source)
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	root := filepath.Clean(destination)
	if err := os.MkdirAll(root, 0o750); err != nil {
		return err
	}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if err := validateArtifactPath(filepath.ToSlash(header.Name)); err != nil {
			return fmt.Errorf("configuration archive: %w", err)
		}
		target := filepath.Clean(filepath.Join(root, filepath.FromSlash(header.Name)))
		if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			return errors.New("configuration archive path escapes destination")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if header.Size < 0 || header.Size > 64<<20 {
				return fmt.Errorf("configuration archive entry %q has an invalid size", header.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			// #nosec G304 -- target passed artifact-path validation, destination containment, and exclusive creation.
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			written, copyErr := io.Copy(file, io.LimitReader(reader, header.Size+1))
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if written != header.Size {
				return fmt.Errorf("configuration archive entry %q size mismatch", header.Name)
			}
		default:
			return fmt.Errorf("configuration archive contains unsupported entry %q", header.Name)
		}
	}
	for _, required := range []string{
		"compose.yaml",
		"content/sigma/windows/kcsp_suspicious_powershell.yml",
		"internal/store/migrations/0001_control_plane.sql",
		"internal/store/clickhouse_migrations/0001_telemetry.sql",
	} {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(required))); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("restored configuration is missing %s", required)
		}
	}
	return nil
}
