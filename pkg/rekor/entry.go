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
	"crypto/sha256"
	"encoding/hex"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

func rekorEntry(payload, signature, cert []byte) *models.Hashedrekord {
	// TODO: Signatures created on a digest using a hash algorithm other than SHA256 will fail
	// upload right now. Plumb information on the hash algorithm used when signing from the
	// SignerVerifier to use for the HashedRekordObj.Data.Hash.Algorithm.
	h := sha256.Sum256(payload)
	re := hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
					Value:     swag.String(hex.EncodeToString(h[:])),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				//Content: strfmt.Base64(signature),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(cert),
				},
			},
		},
	}

	return &models.Hashedrekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.HashedRekordObj,
	}
}
