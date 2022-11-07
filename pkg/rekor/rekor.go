//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rekor

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-openapi/runtime"

	"github.com/sigstore/cosign/pkg/cosign"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Verifier represents a mechanism to get and verify Rekor entries for the given Git commit.
type Verifier interface {
	Verify(ctx context.Context, commitSHA string, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error)
}

// Writer represents a mechanism to write content to Rekor.
type Writer interface {
	Write(ctx context.Context, commitSHA string, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error)
}

// Client implements a basic rekor implementation for writing and verifying Rekor data.
type Client struct {
	*client.Rekor
}

func New(url string, opts ...rekor.Option) (*Client, error) {
	c, err := rekor.GetRekorClient(url, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{
		Rekor: c,
	}, nil
}

func (c *Client) Write(ctx context.Context, commitSHA string, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	pem, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}
	return cosign.TLogUpload(ctx, c.Rekor, sig, []byte(commitSHA), pem)
}

func (c *Client) get(ctx context.Context, data, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	pem, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}

	entries, err := c.findTLogEntries(ctx, data, sig, pem)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("could not find matching tlog entry")

	}

	// TODO: Select matching entry based on committer identity.
	return entries[0], nil
}

// findTLogEntriesByPayloadAndPK is roughly equivalent to cosign.FindTLogEntriesByPayload,
// but also filters by the public key used.
func (c *Client) findTLogEntries(ctx context.Context, payload, sig, pubKey []byte) (uuids []*models.LogEntryAnon, err error) {
	query := &models.SearchLogQuery{}
	query.SetEntries([]models.ProposedEntry{rekorEntry(payload, sig, pubKey)})

	params := entries.NewSearchLogQueryParamsWithContext(ctx)
	params.SetEntry(query)

	resp, err := c.Rekor.Entries.SearchLogQuery(params)
	if err != nil {
		return nil, fmt.Errorf("searching log query: %w", err)
	}
	if len(resp.Payload) == 0 {
		return nil, errors.New("signature not found in transparency log")
	}

	// This may accumulate multiple entries on multiple tree IDs.
	results := make([]*models.LogEntryAnon, 0)
	for _, logEntry := range resp.GetPayload() {
		for k, e := range logEntry {
			// Check body hash matches uuid
			if err := verifyUUID(k, e); err != nil {
				continue
			}
			results = append(results, &e)
		}
	}
	return results, nil
}

func (c *Client) Verify(ctx context.Context, commitSHA string, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	e, err := c.get(ctx, []byte(commitSHA), []byte(sig), cert)
	if err != nil {
		return nil, err
	}
	return e, cosign.VerifyTLogEntry(ctx, c.Rekor, e)
}

// extractCerts is taken from cosign's cmd/cosign/cli/verify/verify_blob.go.
// TODO: Refactor this into a shared lib.
func extractCerts(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.CreateVersionedEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord_v001.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord_v001.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
}

func verifyUUID(uid string, e models.LogEntryAnon) error {
	// Verify and get the UUID.
	u, err := sharding.GetUUIDFromIDString(uid)
	if err != nil {
		return fmt.Errorf("invalid rekor UUID: %w", err)
	}
	raw, _ := hex.DecodeString(u)

	// Verify leaf hash matches hash of the entry body.
	computedLeafHash, err := cosign.ComputeLeafHash(&e)
	if err != nil {
		return err
	}
	if !bytes.Equal(computedLeafHash, raw) {
		return fmt.Errorf("computed leaf hash did not match UUID")
	}
	return nil
}
