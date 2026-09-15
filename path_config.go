package litellm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type config struct {
	URL         string `json:"url"`
	AdminKey    string `json:"admin_key"`
	CACert      string `json:"ca_cert"`
	InsecureTLS bool   `json:"insecure_tls"`
}

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: configPath,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLiteLLM,
		},
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:        framework.TypeString,
				Description: "Base URL of the LiteLLM proxy, e.g. https://litellm.example.com.",
				Required:    true,
			},
			"admin_key": {
				Type:        framework.TypeString,
				Description: "LiteLLM key with proxy admin rights (the master key or a proxy_admin virtual key).",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM CA bundle used to verify the LiteLLM server certificate. Defaults to the system trust store.",
			},
			"insecure_tls": {
				Type:        framework.TypeBool,
				Description: "Skip verification of the LiteLLM server certificate.",
				Default:     false,
			},
		},
		ExistenceCheck: b.configExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
		},
		HelpSynopsis:    "Configure the LiteLLM connection.",
		HelpDescription: "The admin key is verified against LiteLLM on every write and is never returned.",
	}
}

func (b *backend) configExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	cfg, err := getConfig(ctx, req.Storage)
	return cfg != nil, err
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &config{}
	}
	if v, ok := d.GetOk("url"); ok {
		cfg.URL = v.(string)
	}
	if v, ok := d.GetOk("admin_key"); ok {
		cfg.AdminKey = v.(string)
	}
	if v, ok := d.GetOk("ca_cert"); ok {
		cfg.CACert = v.(string)
	}
	if v, ok := d.GetOk("insecure_tls"); ok {
		cfg.InsecureTLS = v.(bool)
	}

	if cfg.URL == "" {
		return logical.ErrorResponse("url is required"), nil
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return logical.ErrorResponse("url must be an http or https URL with a host"), nil
	}
	if cfg.AdminKey == "" {
		return logical.ErrorResponse("admin_key is required"), nil
	}
	c, err := cfg.client()
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := c.checkAdminKey(ctx); err != nil {
		return logical.ErrorResponse("admin_key rejected: %s", err), nil
	}

	entry, err := logical.StorageEntryJSON(configPath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil || cfg == nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]any{
			"url":          cfg.URL,
			"ca_cert":      cfg.CACert,
			"insecure_tls": cfg.InsecureTLS,
		},
	}, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, configPath)
}

func getConfig(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, configPath)
	if err != nil || entry == nil {
		return nil, err
	}
	cfg := &config{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// getClient is the entry point for every path that talks to LiteLLM.
func getClient(ctx context.Context, s logical.Storage) (*client, error) {
	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("LiteLLM connection not configured: write config first")
	}
	return cfg.client()
}

func (cfg *config) client() (*client, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureTLS}
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, errors.New("ca_cert contains no PEM certificates")
		}
		tlsCfg.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	hc := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	return newClient(cfg.URL, cfg.AdminKey, hc), nil
}
