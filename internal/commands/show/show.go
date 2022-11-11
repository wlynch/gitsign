package show

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/pkg/attestation"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/spf13/cobra"
)

const (
	predicateType = "gitsign.sigstore.dev/attestation/git/v0.1"
)

type options struct {
	FlagRemote string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.FlagRemote, "remote", "r", "origin", "make a signature")
}

func (o *options) Run(w io.Writer, args []string) error {
	repo, err := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return err
	}
	revision := "HEAD"
	if len(args) > 0 {
		revision = args[0]
	}

	out, err := statement(repo, o.FlagRemote, revision)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)

	return nil
}

func statement(repo *git.Repository, remote, revision string) (*in_toto.Statement, error) {
	hash, err := repo.ResolveRevision(plumbing.Revision(revision))
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, err
	}

	resolvedRemote, err := repo.Remote(remote)
	if err != nil && err != git.ErrRemoteNotFound {
		fmt.Println(err != nil, err != git.ErrRemoteNotFound)
		return nil, err
	}

	parents := make([]string, 0, len(commit.ParentHashes))
	for _, p := range commit.ParentHashes {
		if !p.IsZero() {
			parents = append(parents, p.String())
		}
	}

	predicate := &attestation.GitCommitPredicate{
		Commit: &attestation.Commit{
			Tree:    commit.TreeHash.String(),
			Parents: parents,
			Author: &attestation.Author{
				Name:  commit.Author.Name,
				Email: commit.Author.Email,
				Date:  commit.Author.When,
			},
			Committer: &attestation.Author{
				Name:  commit.Committer.Name,
				Email: commit.Committer.Email,
				Date:  commit.Committer.When,
			},
			Message: commit.Message,
		},
		Signature: commit.PGPSignature,
	}

	pem, _ := pem.Decode([]byte(commit.PGPSignature))
	if pem != nil {
		sigs, err := parseSignature(pem.Bytes)
		if err != nil {
			return nil, err
		}
		predicate.SignerInfo = sigs
	}

	remoteName := ""
	if resolvedRemote != nil && len(resolvedRemote.Config().URLs) > 0 {
		remoteName = resolvedRemote.Config().URLs[0]
	}
	return &in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type: in_toto.StatementInTotoV01,
			Subject: []in_toto.Subject{{
				Name: remoteName,
				Digest: v02.DigestSet{
					"sha1": hash.String(),
				},
			}},
			PredicateType: predicateType,
		},
		Predicate: predicate,
	}, nil
}

func parseSignature(raw []byte) ([]*attestation.SignerInfo, error) {
	ci, err := protocol.ParseContentInfo(raw)
	if err != nil {
		return nil, err
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		return nil, err
	}

	certs, err := sd.X509Certificates()
	if err != nil {
		return nil, err
	}

	out := make([]*attestation.SignerInfo, 0, len(sd.SignerInfos))
	for _, si := range sd.SignerInfos {
		cert, err := si.FindCertificate(certs)
		if err != nil {
			continue
		}
		b, err := cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return nil, err
		}
		sa, err := si.SignedAttrs.MarshaledForVerification()
		if err != nil {
			return nil, err
		}
		out = append(out, &attestation.SignerInfo{
			Certificate: string(b),
			Attributes:  base64.StdEncoding.EncodeToString(sa),
		})
	}

	return out, nil
}

func New(cfg *config.Config) *cobra.Command {
	o := &options{}

	cmd := &cobra.Command{
		Use:   "show [revision]",
		Short: "Show source attestation information",
		Long: `Show source attestation information

Prints an in-toto style attestation for the specified revision.
If no revision is specified, HEAD is used.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Run(os.Stdout, args)
		},
	}
	o.AddFlags(cmd)

	return cmd
}
