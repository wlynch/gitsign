package show

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/objfile"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-cmp/cmp"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/gitsign/pkg/attestation"
)

func TestShow(t *testing.T) {
	storage := memory.NewStorage()
	repo := &git.Repository{
		Storer: storage,
	}
	if err := repo.SetConfig(&config.Config{
		Remotes: map[string]*config.RemoteConfig{
			"origin": {
				Name: "origin",
				URLs: []string{"git@github.com:wlynch/gitsign.git"},
			},
		},
	}); err != nil {
		t.Fatalf("error setting git config: %v", err)
	}

	// Expect files in testdata directory:
	//  foo.in.txt -> foo.out.json
	// IMPORTANT: When generating new test files, use a command like `git cat-file commit main > foo.in.txt`.
	// If you try and copy/paste the content, you may get burned by file encodings and missing \r characters.
	for _, tc := range []string{
		"fulcio-cert",
		"gpg",
	} {
		t.Run(tc, func(t *testing.T) {
			raw, err := os.ReadFile(fmt.Sprintf("testdata/%s.in.txt", tc))
			if err != nil {
				t.Fatalf("error reading input: %v", err)
			}
			obj := storage.NewEncodedObject()
			obj.SetType(plumbing.CommitObject)
			w, err := obj.Writer()
			if err != nil {
				t.Fatalf("error getting git object writer: %v", err)
			}
			_, err = w.Write(raw)
			if err != nil {
				t.Fatalf("error writing git commit: %v", err)
			}
			h, err := storage.SetEncodedObject(obj)
			if err != nil {
				t.Fatalf("error storing git commit: %v", err)
			}

			got, err := statement(repo, "origin", h.String())
			if err != nil {
				t.Fatalf("statement(): %v", err)
			}

			wantRaw, err := os.ReadFile(fmt.Sprintf("testdata/%s.out.json", tc))
			if err != nil {
				t.Fatalf("error reading want json: %v", err)
			}
			want := &in_toto.Statement{
				Predicate: &attestation.GitCommitPredicate{},
			}
			if err := json.Unmarshal(wantRaw, want); err != nil {
				t.Fatalf("error decoding want json: %v", err)
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestRead(t *testing.T) {
	b := bytes.NewBufferString(`tree 194fca354a2439028e347ce5e19e4db45bd708a6
parent 2eaf8fc6d66505baa90640d018e1131cd8e99334
author Billy Lynch <billy@chainguard.dev> 1668460399 -0500
committer Billy Lynch <billy@chainguard.dev> 1668460399 -0500
gpgsig -----BEGIN SIGNED MESSAGE-----
	MIIEAwYJKoZIhvcNAQcCoIID9DCCA/ACAQExDTALBglghkgBZQMEAgEwCwYJKoZI
	hvcNAQcBoIICpDCCAqAwggImoAMCAQICFFTzLmXKAlKX5xTUaYoUE5giCxZvMAoG
	CCqGSM49BAMDMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2ln
	c3RvcmUtaW50ZXJtZWRpYXRlMB4XDTIyMTExNDIxMTMyM1oXDTIyMTExNDIxMjMy
	M1owADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH++UCDlF9MaQCSgDKQ0bWhD
	eOmTrk1sEHw9Oel1eCyrr3SFhDAghcO3VwO7baYmL16fUwRYwMhj5urowsLVrjKj
	ggFFMIIBQTAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYD
	VR0OBBYEFHMPDOs6IDY/iRnVqacIj/yvJbNpMB8GA1UdIwQYMBaAFN/T6c9WJBGW
	+ajY6ShVosYuGGQ/MCIGA1UdEQEB/wQYMBaBFGJpbGx5QGNoYWluZ3VhcmQuZGV2
	MCkGCisGAQQBg78wAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTCBigYK
	KwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAv
	Ke6OAAABhHf9WZAAAAQDAEcwRQIgV8anMDEjbHI/WvGxpJmm44DgBTYf5bkfBJIP
	6FJtqXYCIQD/noLzthDKgjrXoiep/BqqnygoTRM9HKim+DRMbwHteDAKBggqhkjO
	PQQDAwNoADBlAjEAvHvqOAKT34QQx9PSuOswQfquByALdzA1ES0nx4M5i47kqNeE
	Bl612/hYTD1ydpLIAjBTWiHDtdxM9rriTIyGGJubC0+vNcccsURDTJ+A3XnMAER3
	ikl/cJ2wG9c8ZN7AUS8xggElMIIBIQIBATBPMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
	LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlAhRU8y5lygJSl+cU
	1GmKFBOYIgsWbzALBglghkgBZQMEAgGgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
	AQcBMBwGCSqGSIb3DQEJBTEPFw0yMjExMTQyMTEzMjNaMC8GCSqGSIb3DQEJBDEi
	BCC9Yk93XCRKy6FPCb8dAqjdWpjb1NIbFtTo9CP6yYOZQjAKBggqhkjOPQQDAgRH
	MEUCIQCq+2Zs0bBcAAciePeeRpzmfVJ2gEu7sGngy+TcYpS0ugIgL9Qix3V8taBV
	+Tb6rMZmt80sfGsYhUqE8KsIF1AEc+8=
	-----END SIGNED MESSAGE-----

add sample
`)
	objfile.NewReader(b)
}
