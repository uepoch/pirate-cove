package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/pluginutil"
	"os"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"

	"github.com/hashicorp/vault/vault"
	"log"

	"github.com/hashicorp/vault/logical/plugin"
	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/helper/wrapping"
	"github.com/hashicorp/vault/helper/parseutil"
)

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: FactoryType(logical.TypeLogical),
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
		os.Exit(2)
	}
}

func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		b, _ := PirateCoveBackendFactory(ctx, config)
		spew.Config.MaxDepth = 3
		if config == nil {
			return nil, fmt.Errorf("Configuation passed into backend is nil")
		}

		b.BackendType = backendType
		if err := b.Backend.Setup(ctx, config); err != nil {
			return nil, err
		}
		return b, nil
	}
}

func (b *PirateCoveBackend) extractUser(req *logical.Request) (string, error) {
	//TODO: Implement proper extracting from different patterns ( Entity ? )
	//TODO: Remove logic from wrapUser and include it here

	s := req.DisplayName
	b.Logger().Trace(fmt.Sprintf("pirateCove Isolating user", s))
	splitted := strings.SplitN(s, "-", 2)
	if len(splitted) != 2 {
		b.Logger().Error(fmt.Sprintf("pirateCove Error isolating user from %s", s))
		return "", fmt.Errorf("Error while isolating user from %s", s)
	}
	return splitted[1], nil
}

func (b *PirateCoveBackend) wrapMe(fn func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error)) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		//b.Logger().Warn(spew.Sdump(req.Auth))
		//b.Logger().Warn(spew.Sdump(req.Storage))
		user, err := b.extractUser(req)
		if err != nil {
			return nil, err
		}
		req.Path = strings.Replace(req.Path, "me", user, 1)
		b.Logger().Info(fmt.Sprintf("Accessing: %s", req.Path))
		return fn(ctx, req, data)
	}
}

//TODO: Implement authorization
func (b *PirateCoveBackend) wrapUser(fn framework.OperationFunc) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		_, _, err := data.GetOkErr("name")
		if err != nil {
			return nil, err
		}
		req.Path = strings.TrimPrefix(req.Path, "users/")
		b.Logger().Info(fmt.Sprintf("Accessing: %s", req.Path))
		return fn(ctx, req, data)
	}
}

// PirateCoveBackendFactory constructs a new pirateCove backend
func PirateCoveBackendFactory(ctx context.Context, conf *logical.BackendConfig) (*PirateCoveBackend, error) {
	//TODO: Use the conf to configure at least leases
	var b PirateCoveBackend
	b.Backend = &framework.Backend{
		Help:  strings.TrimSpace(pirateCoveHelp),
		Clean: func(ctx context.Context) {},
		PathsSpecial: &logical.Paths{},
		Paths: []*framework.Path{
			{
				Pattern: "users/(?P<name>[a-z]\\.[a-z]+)/.*",
				Fields: map[string]*framework.FieldSchema{
					"name": {
						Type:        framework.TypeString,
						Default:     "",
						Description: "Name of the user you wish to visit.",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation:   b.wrapUser(b.handleRead),
					logical.CreateOperation: b.wrapUser(b.handleWrite),
					logical.UpdateOperation: b.wrapUser(b.handleWrite),
					logical.DeleteOperation: b.wrapUser(b.handleDelete),
					logical.ListOperation:   b.wrapUser(b.handleList),
				},
				//TODO: Implement something that work....
				//ExistenceCheck: b.handleExistenceCheck,

				HelpSynopsis:    strings.TrimSpace(pirateCoveHelpSynopsis),
				HelpDescription: strings.TrimSpace(pirateCoveHelpDescription),
			},
			{
				Pattern: "me/.*",

				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation:   b.wrapMe(b.handleRead),
					logical.CreateOperation: b.wrapMe(b.handleWrite),
					logical.UpdateOperation: b.wrapMe(b.handleWrite),
					logical.DeleteOperation: b.wrapMe(b.handleDelete),
					logical.ListOperation:   b.wrapMe(b.handleList),
				},
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}

	return &b, nil
}

// PirateCoveBackend is used for storing secrets directly into the physical
// backend. The secrets are encrypted in the durable storage.
//Since i'm relying A LOT on Passthrough Backend, maybe it will be better to include it, and not a generic Framework
type PirateCoveBackend struct {
	*framework.Backend

	saltUUID    string
	storageView logical.Storage
}

func (b *PirateCoveBackend) revoke(ctx context.Context, saltedToken string) error {
	if saltedToken == "" {
		return fmt.Errorf("pirateCove: client token empty during revocation")
	}

	if err := logical.ClearView(ctx, b.storageView.(*vault.BarrierView).SubView(saltedToken+"/")); err != nil {
		return err
	}

	return nil
}

func (b *PirateCoveBackend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.ClientToken+"/"+req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %v", err)
	}

	return out != nil, nil
}

func (b *PirateCoveBackend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Read the path
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)

	}

	// Fast-path the no data case
	if out == nil {
		return nil, nil
	}

	// Decode the data
	var rawData map[string]interface{}

	if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %v", err)
	}

	var resp *logical.Response
	resp = &logical.Response{
		Secret: &logical.Secret{},
		Data:   rawData,
	}

	// Ensure seal wrapping is carried through if the response is
	// response-wrapped
	if out.SealWrap {
		if resp.WrapInfo == nil {
			resp.WrapInfo = &wrapping.ResponseWrapInfo{}
		}
		resp.WrapInfo.SealWrap = out.SealWrap
	}

	// Check if there is a ttl key
	ttlDuration := b.System().DefaultLeaseTTL()
	ttlRaw, ok := rawData["ttl"]
	if !ok {
		ttlRaw, ok = rawData["lease"]
	}
	if ok {
		dur, err := parseutil.ParseDurationSecond(ttlRaw)
		if err == nil {
			ttlDuration = dur
		}

	}

	resp.Secret.TTL = ttlDuration

	return resp, nil
}

func (b *PirateCoveBackend) handleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Check that some fields are given
	if len(req.Data) == 0 {
		return logical.ErrorResponse("missing data fields"), nil
	}

	// JSON encode the data
	buf, err := json.Marshal(req.Data)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %v", err)
	}

	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   req.Path,
		Value: buf,
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	return nil, nil
}

func (b *PirateCoveBackend) handleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Delete the key at the request path
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *PirateCoveBackend) handleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Right now we only handle directories, so ensure it ends with /; however,
	// some physical backends may not handle the "/" case properly, so only add
	// it if we're not listing the root
	path := req.Path
	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	// List the keys at the prefix given by the request
	keys, err := req.Storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	// Generate the response
	return logical.ListResponse(keys), nil
}

const pirateCoveHelp = `
The pirateCove backend reads and writes arbitrary secrets to the backend.
The secrets are encrypted/decrypted by Vault: they are never stored
unencrypted in the backend and the backend never has an opportunity to
see the unencrypted value.

This backend differs from the "cubbyhole" KV by keeping persistent namespace
and handling QoL feature such as ACL and sharing.
`

const pirateCoveHelpSynopsis = `
Pass-through secret storage to a user-specific pirateCove in the storage
backend, allowing you to read/write arbitrary data into secret storage.
`

const pirateCoveHelpDescription = `
The pirateCove backend reads and writes arbitrary data into secret storage,
encrypting it along the way.

The view into the pirateCove storage space is different for each user; Each 
user has a chest that he owns. Later you will be able to implement ACL for sharing
`
