package cmd

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"io/ioutil"
	"crypto/x509"

	"github.com/codenotary/cas/pkg/store"
	lc "github.com/vchain-us/ledger-compliance-go/grpcclient"
	schema "github.com/vchain-us/ledger-compliance-go/schema"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/testifysec/witness/cmd/witness/options"
	"github.com/testifysec/witness/pkg/attestation/product"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/log"
)

type LcAttachment struct {
	Filename string `json:"filename"`
	Hash     string `json:"hash"`
	Mime     string `json:"mime"`
}

type LcArtifact struct {
	Kind        string                 `json:"kind"`
	Name        string                 `json:"name"`
	Hash        string                 `json:"hash"`
	Size        uint64                 `json:"size"`
	Timestamp   time.Time              `json:"timestamp,omitempty"`
	ContentType string                 `json:"contentType"`
	Metadata    map[string]interface{} `json:"metadata"`
	Attachments []LcAttachment         `json:"attachments"`
	Signer      string                 `json:"signer"`
	Status      uint64                 `json:"status"` // 0 means "Trusted"
}

func casNotarize(ro options.RunOptions, attestor *product.Attestor, buf []byte) error {
	log.Infof("Notarizing with CAS ...")

	// TODO: read CAS config from default location, consider adding an option to specify the directory
	if err := store.SetDefaultDir(); err != nil {
		return err
	}
	if err := store.LoadConfig(); err != nil {
		return nil
	}
	config := store.Config().CurrentContext
	
	host := config.LcHost
	if config.LcHost == "" {
		return errors.New("log in to CAS first")
	}
	port, err := strconv.Atoi(config.LcPort)
	if err != nil {
		return errors.New("CAS port is invalid")
	}

	var tlsCredentials credentials.TransportCredentials
	if config.LcNoTls {
		tlsCredentials = insecure.NewCredentials()
	} else if config.LcSkipTlsVerify {
		tlsCredentials = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	} else if config.LcCert != "" {
		tlsCredentials, err = loadTLSCertificate(config.LcCert)
		if err != nil {
			return fmt.Errorf("cannot load TLS credentials: %s", err)
		}
	} else {
		tlsCredentials = credentials.NewTLS(&tls.Config{})
	}

	dialOptions := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                20 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(32 * 1024 * 1024)),
		grpc.WithTransportCredentials(tlsCredentials),
	}

	lcClient := lc.NewLcClient(
		lc.DialOptions(dialOptions),
		lc.ApiKey(ro.CasApiKey),
		lc.MetadataPairs([]string{
			"version", "0",
			"lc-plugin-type", "witness",
		}),
		lc.Host(host),
		lc.Port(port),
		lc.Dir(store.CurrentConfigFilePath()),
		// TODO consider adding server public key option with lc.ServerSigningPubKey()

	)
	err = lcClient.Connect()
	if err != nil {
		return err
	}
	defer lcClient.Disconnect()

	fields := strings.Split(ro.CasApiKey, ".")
	if len(fields) < 2 {
		return errors.New("malformed CAS API key")
	}
	signerID := fields[0]

	aHash := sha256.Sum256(buf)
	attachmentHash := hex.EncodeToString(aHash[:])

	for name, product := range attestor.Products() {
		hashType := crypto.SHA256
		hash, ok := product.Digest[hashType]
		if !ok {
			hashType = crypto.SHA1
			hash, ok = product.Digest[hashType]
			if !ok {
				return errors.New("cannot find supported hash type")
			}
		}
		hashTypeName, _ := cryptoutil.HashToString(hashType)
		artifact := LcArtifact{
			Name:        name,
			Kind:        "file",
			Hash:        hash,
			ContentType: product.MimeType,
			Timestamp:   time.Now(),
			Signer:      signerID,
			Attachments: []LcAttachment{
				{
					Filename: "witness.json",
					Mime:     "application/json",
					Hash:     attachmentHash,
				},
			},
			Metadata: map[string]interface{}{
				"hashtype": hashTypeName,
			},
		}
		encodedArtifact, err := json.Marshal(artifact)
		if err != nil {
			return err
		}

		req := schema.VCNArtifactsRequest{
			Artifacts: []*schema.VCNArtifact{
				{
					Artifact: encodedArtifact,
					Attachments: []*schema.VCNAttachment{
						{
							Content: buf,
						},
					},
				},
			},
		}

		md := metadata.Pairs(
			"lc-plugin-type", "witness",
			"vcn-command", "notarize",
		)
		ctx := metadata.NewOutgoingContext(context.Background(), md)

		resp, err := lcClient.VCNSetArtifacts(ctx, &req)
		if err != nil {
			return err
		}
		log.Infof("Product '%s' notarized, txn %d", name, resp.Transaction.GetId())
	}

	return nil
}

func loadTLSCertificate(certPath string) (credentials.TransportCredentials, error) {
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(cert) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}
	config := &tls.Config{
		RootCAs: certPool,
	}
	return credentials.NewTLS(config), nil
}
