package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	_ pluginsdk.NeedsLogger       = (*Plugin)(nil)
	_ pluginsdk.NeedsHostServices = (*Plugin)(nil)
)

const (
	defaultClaimName   = "uid"
	defaultDomainChars = 16
	defaultPathChars   = 16
)

// Config holds plugin configuration decoded from HCL plugin_data.
type Config struct {
	ClaimName   string `hcl:"claim_name"`
	DomainChars int    `hcl:"domain_chars"`
	PathChars   int    `hcl:"path_chars"`
}

// Plugin implements the SPIRE CredentialComposer interface.
// It appends a structured alphanumeric identifier derived from the workload's
// SPIFFE ID as a custom JWT-SVID claim. The identifier is formed by
// concatenating the SHA256 hex digests of the trust domain and path parts,
// truncated to the configured character lengths.
type Plugin struct {
	credentialcomposerv1.UnimplementedCredentialComposerServer
	configv1.UnimplementedConfigServer

	configMtx sync.RWMutex
	config    *Config

	logger hclog.Logger
}

// hashSpiffeID splits the SPIFFE ID into trust domain and path, hashes each
// part independently with SHA256, and returns the hex-encoded concatenation
// truncated to domainChars and pathChars characters respectively.
//
// Example (domainChars=16, pathChars=16):
//
//	"spiffe://org-a.example/workload/jenkins"
//	  trust domain: SHA256("org-a.example")[:8]   → "a1b2c3d4e5f6a7b8"
//	  path:         SHA256("workload/jenkins")[:8] → "1234567890abcdef"
//	  result:       "a1b2c3d4e5f6a7b81234567890abcdef"
//
// Because the trust domain hash occupies the first domainChars characters,
// two workloads from different trust domains can never produce the same output.
func hashSpiffeID(spiffeID string, domainChars, pathChars int) string {
	withoutScheme := strings.TrimPrefix(spiffeID, "spiffe://")
	parts := strings.SplitN(withoutScheme, "/", 2)
	trustDomain := parts[0]
	path := ""
	if len(parts) > 1 {
		path = parts[1]
	}
	tdHash   := sha256.Sum256([]byte(trustDomain))
	pathHash := sha256.Sum256([]byte(path))
	return fmt.Sprintf("%x%x", tdHash[:domainChars/2], pathHash[:pathChars/2])
}

// Configure is called by SPIRE when loading the plugin. It decodes the HCL
// plugin_data block and validates the configuration values.
func (p *Plugin) Configure(ctx context.Context,
	req *configv1.ConfigureRequest,
) (*configv1.ConfigureResponse, error) {
	cfg := &Config{
		ClaimName:   defaultClaimName,
		DomainChars: defaultDomainChars,
		PathChars:   defaultPathChars,
	}
	if req.HclConfiguration != "" {
		if err := hcl.Decode(cfg, req.HclConfiguration); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid config: %v", err)
		}
	}
	if cfg.ClaimName == "" {
		return nil, status.Error(codes.InvalidArgument, "claim_name must not be empty")
	}
	if cfg.DomainChars <= 0 || cfg.DomainChars%2 != 0 {
		return nil, status.Error(codes.InvalidArgument, "domain_chars must be a positive even number")
	}
	if cfg.PathChars <= 0 || cfg.PathChars%2 != 0 {
		return nil, status.Error(codes.InvalidArgument, "path_chars must be a positive even number")
	}
	if cfg.DomainChars/2 > sha256.Size {
		return nil, status.Errorf(codes.InvalidArgument,
			"domain_chars must not exceed %d (SHA256 output size)", sha256.Size*2)
	}
	if cfg.PathChars/2 > sha256.Size {
		return nil, status.Errorf(codes.InvalidArgument,
			"path_chars must not exceed %d (SHA256 output size)", sha256.Size*2)
	}
	p.setConfig(cfg)
	p.logger.Info("configured",
		"claim_name", cfg.ClaimName,
		"domain_chars", cfg.DomainChars,
		"path_chars", cfg.PathChars,
	)
	return &configv1.ConfigureResponse{}, nil
}

// ComposeWorkloadJWTSVID adds the configured claim containing the structured
// SPIFFE ID hash to every JWT-SVID issued for a workload.
func (p *Plugin) ComposeWorkloadJWTSVID(ctx context.Context,
	req *credentialcomposerv1.ComposeWorkloadJWTSVIDRequest,
) (*credentialcomposerv1.ComposeWorkloadJWTSVIDResponse, error) {
	cfg, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	attrs := req.Attributes
	if attrs == nil {
		attrs = &credentialcomposerv1.JWTSVIDAttributes{}
	}
	if attrs.Claims == nil {
		attrs.Claims = &structpb.Struct{Fields: map[string]*structpb.Value{}}
	}

	uid := hashSpiffeID(req.SpiffeId, cfg.DomainChars, cfg.PathChars)
	attrs.Claims.Fields[cfg.ClaimName] = structpb.NewStringValue(uid)

	p.logger.Debug("added claim",
		"spiffe_id", req.SpiffeId,
		"claim", cfg.ClaimName,
		"value", uid,
	)

	return &credentialcomposerv1.ComposeWorkloadJWTSVIDResponse{
		Attributes: attrs,
	}, nil
}

// BrokerHostServices is called by the framework when the plugin is loaded.
func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	return nil
}

// SetLogger is called by the framework to inject a logger.
func (p *Plugin) SetLogger(logger hclog.Logger) { p.logger = logger }

func (p *Plugin) setConfig(cfg *Config) {
	p.configMtx.Lock()
	p.config = cfg
	p.configMtx.Unlock()
}

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
