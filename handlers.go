package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/parseutil"
	"github.com/hashicorp/vault/helper/wrapping"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/vault"
)

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
