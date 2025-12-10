package config

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
)

const defaultBundleSizeLimit = 8 << 20 // 8 MiB

// PolicyBundleDescriptor describes how to obtain and verify a policy bundle composed of multiple artifacts.
type PolicyBundleDescriptor struct {
	ID        string                     `json:"id" yaml:"id"`
	Name      string                     `json:"name" yaml:"name"`
	Version   int                        `json:"version" yaml:"version"`
	Revision  string                     `json:"revision" yaml:"revision"`
	Path      string                     `json:"path" yaml:"path"`
	SizeLimit int64                      `json:"sizeLimit" yaml:"sizeLimit"`
	Labels    map[string]string          `json:"labels" yaml:"labels"`
	Artifacts []BundleArtifactDescriptor `json:"artifacts" yaml:"artifacts"`
}

// BundleArtifactDescriptor declares how to retrieve an artifact within a bundle.
type BundleArtifactDescriptor struct {
	Name        string            `json:"name" yaml:"name"`
	Path        string            `json:"path" yaml:"path"`
	Type        string            `json:"type" yaml:"type"`
	MediaType   string            `json:"mediaType" yaml:"mediaType"`
	Encoding    string            `json:"encoding" yaml:"encoding"`
	Compression string            `json:"compression" yaml:"compression"`
	SHA256      string            `json:"sha256" yaml:"sha256"`
	Metadata    map[string]string `json:"metadata" yaml:"metadata"`
}

type rawArtifact struct {
	descriptor BundleArtifactDescriptor
	data       []byte
	digest     string
	limit      int64
}

// Validate ensures the descriptor is well formed before loading.
func (d PolicyBundleDescriptor) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return errors.New("policy bundle id is required")
	}
	if d.Version <= 0 {
		return fmt.Errorf("policy bundle %s requires version greater than zero", d.ID)
	}
	if len(d.Artifacts) == 0 {
		return fmt.Errorf("policy bundle %s defines no artifacts", d.ID)
	}
	seen := make(map[string]struct{}, len(d.Artifacts))
	for _, artifact := range d.Artifacts {
		name := strings.TrimSpace(artifact.Name)
		if name == "" {
			return fmt.Errorf("policy bundle %s: artifact name is required", d.ID)
		}
		if strings.TrimSpace(artifact.Type) == "" {
			return fmt.Errorf("policy bundle %s: artifact %s requires type", d.ID, artifact.Name)
		}
		if strings.TrimSpace(artifact.Path) == "" && strings.TrimSpace(d.Path) == "" {
			return fmt.Errorf("policy bundle %s: artifact %s requires path", d.ID, artifact.Name)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("policy bundle %s: duplicate artifact name %s", d.ID, artifact.Name)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// Clone returns a deep copy of the descriptor.
func (d PolicyBundleDescriptor) Clone() PolicyBundleDescriptor {
	clone := PolicyBundleDescriptor{
		ID:        d.ID,
		Name:      d.Name,
		Version:   d.Version,
		Revision:  d.Revision,
		Path:      d.Path,
		SizeLimit: d.SizeLimit,
	}
	if len(d.Labels) > 0 {
		clone.Labels = copyStringMap(d.Labels)
	}
	if len(d.Artifacts) > 0 {
		clone.Artifacts = make([]BundleArtifactDescriptor, len(d.Artifacts))
		for i, artifact := range d.Artifacts {
			clone.Artifacts[i] = artifact.Clone()
		}
	}
	return clone
}

// Clone returns a deep copy of the artifact descriptor.
func (a BundleArtifactDescriptor) Clone() BundleArtifactDescriptor {
	clone := BundleArtifactDescriptor{
		Name:        a.Name,
		Path:        a.Path,
		Type:        a.Type,
		MediaType:   a.MediaType,
		Encoding:    a.Encoding,
		Compression: a.Compression,
		SHA256:      a.SHA256,
	}
	if len(a.Metadata) > 0 {
		clone.Metadata = copyStringMap(a.Metadata)
	}
	return clone
}

func (d PolicyBundleDescriptor) effectiveSizeLimit() int64 {
	if d.SizeLimit > 0 {
		return d.SizeLimit
	}
	return defaultBundleSizeLimit
}

// LoadPolicyBundle reads, verifies, and normalises artifacts according to the descriptor.
func LoadPolicyBundle(desc PolicyBundleDescriptor) (*domain.PolicyBundle, error) {
	if err := desc.Validate(); err != nil {
		return nil, err
	}

	limit := desc.effectiveSizeLimit()
	basePath := strings.TrimSpace(desc.Path)

	rawArtifacts := make([]rawArtifact, 0, len(desc.Artifacts))
	for _, artifactDesc := range desc.Artifacts {
		resolvedPath := artifactDesc.Path
		if !filepath.IsAbs(resolvedPath) {
			if basePath != "" {
				resolvedPath = filepath.Join(basePath, artifactDesc.Path)
			}
		}
		resolvedPath = filepath.Clean(resolvedPath)

		data, digest, err := readArtifact(resolvedPath, limit, artifactDesc.SHA256)
		if err != nil {
			return nil, fmt.Errorf("load artifact %s: %w", artifactDesc.Name, err)
		}

		rawArtifacts = append(rawArtifacts, rawArtifact{
			descriptor: artifactDesc,
			data:       data,
			digest:     digest,
			limit:      limit,
		})
	}

	processor := NewPolicyProcessor()
	return processor.Normalize(desc, rawArtifacts)
}

func readArtifact(path string, limit int64, expectedDigest string) ([]byte, string, error) {
	if path == "" {
		return nil, "", errors.New("artifact path is empty")
	}

	file, err := os.Open(path) //nolint:gosec // G304: Path is from trusted control plane configuration
	if err != nil {
		return nil, "", fmt.Errorf("open: %w", err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, "", fmt.Errorf("stat: %w", err)
	}
	if info.Size() == 0 {
		return nil, "", errors.New("artifact is empty")
	}
	if limit > 0 && info.Size() > limit {
		return nil, "", fmt.Errorf("artifact exceeds size limit (%d bytes)", limit)
	}

	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil, "", fmt.Errorf("read: %w", err)
	}

	digest := computeSHA256Hex(data)
	if err := verifyDigest(expectedDigest, digest); err != nil {
		return nil, "", err
	}

	return data, digest, nil
}

func computeSHA256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func verifyDigest(expected, actual string) error {
	if strings.TrimSpace(expected) == "" {
		return nil
	}
	normalized := normalizeDigest(expected)
	if normalized != actual {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", normalized, actual)
	}
	return nil
}

func normalizeDigest(value string) string {
	lower := strings.TrimSpace(strings.ToLower(value))
	return strings.TrimPrefix(lower, "sha256:")
}

// PolicyProcessor converts raw artifact payloads into domain policy artifacts.
type PolicyProcessor struct {
	now func() time.Time
}

// NewPolicyProcessor constructs a processor with a configurable clock for testing.
func NewPolicyProcessor() PolicyProcessor {
	return PolicyProcessor{now: time.Now}
}

// Normalize converts raw artifacts into a domain policy bundle with decoded payloads.
func (p PolicyProcessor) Normalize(desc PolicyBundleDescriptor, artifacts []rawArtifact) (*domain.PolicyBundle, error) {
	if len(artifacts) == 0 {
		return nil, fmt.Errorf("policy bundle %s contains no artifacts", desc.ID)
	}

	bundle := &domain.PolicyBundle{
		ID:        desc.ID,
		Name:      desc.Name,
		Version:   desc.Version,
		Revision:  desc.Revision,
		Labels:    copyStringMap(desc.Labels),
		Artifacts: make(map[string]domain.PolicyArtifact, len(artifacts)),
	}

	now := p.now().UTC()
	bundle.CreatedAt = now
	bundle.UpdatedAt = now

	for _, raw := range artifacts {
		name := strings.TrimSpace(raw.descriptor.Name)
		if name == "" {
			return nil, fmt.Errorf("policy bundle %s: artifact name is required", desc.ID)
		}
		if _, exists := bundle.Artifacts[name]; exists {
			return nil, fmt.Errorf("policy bundle %s: duplicate artifact %s", desc.ID, name)
		}

		payload, err := p.materializeArtifact(raw)
		if err != nil {
			return nil, fmt.Errorf("artifact %s: %w", name, err)
		}

		artifact := domain.PolicyArtifact{
			Type:        strings.TrimSpace(raw.descriptor.Type),
			MediaType:   strings.TrimSpace(raw.descriptor.MediaType),
			Encoding:    strings.TrimSpace(strings.ToLower(raw.descriptor.Encoding)),
			Compression: normalizedCompression(raw.descriptor.Compression),
			Digest:      raw.digest,
			Data:        payload,
			Metadata:    copyStringMap(raw.descriptor.Metadata),
		}

		bundle.Artifacts[name] = artifact
	}

	if len(bundle.Artifacts) == 0 {
		return nil, fmt.Errorf("policy bundle %s produced no artifacts", desc.ID)
	}

	return bundle, nil
}

func (p PolicyProcessor) materializeArtifact(raw rawArtifact) ([]byte, error) {
	data := append([]byte(nil), raw.data...)
	compression := normalizedCompression(raw.descriptor.Compression)

	switch compression {
	case "", "none":
		// no-op
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decompress gzip: %w", err)
		}
		defer func() { _ = reader.Close() }()
		decompressed, err := io.ReadAll(io.LimitReader(reader, raw.limit))
		if err != nil {
			return nil, fmt.Errorf("read gzip: %w", err)
		}
		data = decompressed
	default:
		return nil, fmt.Errorf("unsupported compression %q", raw.descriptor.Compression)
	}

	encoding := strings.TrimSpace(strings.ToLower(raw.descriptor.Encoding))
	switch encoding {
	case "", "binary", "none":
		// keep raw bytes
	case "base64":
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(decoded, data)
		if err != nil {
			return nil, fmt.Errorf("decode base64: %w", err)
		}
		data = decoded[:n]
	default:
		return nil, fmt.Errorf("unsupported encoding %q", raw.descriptor.Encoding)
	}

	return data, nil
}

func normalizedCompression(value string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	switch trimmed {
	case "", "none":
		return ""
	default:
		return trimmed
	}
}

// LoadPolicyBundleFromDomain loads a policy bundle using a domain descriptor.
func LoadPolicyBundleFromDomain(d domain.PolicyBundleDescriptor) (*domain.PolicyBundle, error) {
artifacts := make([]BundleArtifactDescriptor, len(d.Artifacts))
for i, a := range d.Artifacts {
artifacts[i] = BundleArtifactDescriptor{
Name:        a.Name,
Path:        a.Path,
Type:        a.Type,
MediaType:   a.MediaType,
Encoding:    a.Encoding,
Compression: a.Compression,
SHA256:      a.SHA256,
Metadata:    a.Metadata,
}
}

configDesc := PolicyBundleDescriptor{
ID:        d.ID,
Name:      d.Name,
Version:   d.Version,
Revision:  d.Revision,
Path:      d.Path,
SizeLimit: d.SizeLimit,
Labels:    d.Labels,
Artifacts: artifacts,
}

return LoadPolicyBundle(configDesc)
}

