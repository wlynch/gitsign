package attestation

import (
	"time"
)

type GitCommitPredicate struct {
	Commit    *Commit `json:"source,omitempty"`
	Signature string  `json:"signature,omitempty"`
	// SignerInfo contains select fields from the PKCS7 SignerInfo.
	// This is intended as a convenience for consumers to access relevant
	// fields like certificate instead of needing to parse the signature.
	// See https://datatracker.ietf.org/doc/html/rfc5652#section-5.3 for details.
	SignerInfo []*SignerInfo `json:"signer_info,omitempty"`
}

type Commit struct {
	Tree      string   `json:"tree,omitempty"`
	Parents   []string `json:"parents,omitempty"`
	Author    *Author  `json:"author,omitempty"`
	Committer *Author  `json:"committer,omitempty"`
	Message   string   `json:"message,omitempty"`
}

type Author struct {
	Name  string    `json:"name,omitempty"`
	Email string    `json:"email,omitempty"`
	Date  time.Time `json:"date,omitempty"`
}

type SignerInfo struct {
	// Attributes contains a base64 encoded ASN.1 marshalled signed attributes.
	// See https://datatracker.ietf.org/doc/html/rfc5652#section-5.6 for more details.
	Attributes  string `json:"attributes,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}
