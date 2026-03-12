package plc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/util"
	"pkg.rbrt.fr/vow/identity"
)

type Client struct {
	h              *http.Client
	service        string
	pdsHostname    string
	rotationKey    *atcrypto.PrivateKeyK256
	serviceAuthKey *atcrypto.PrivateKeyP256
}

type ClientArgs struct {
	H              *http.Client
	Service        string
	RotationKey    []byte
	PdsHostname    string
	ServiceAuthKey *atcrypto.PrivateKeyP256
}

func NewClient(args *ClientArgs) (*Client, error) {
	if args.Service == "" {
		args.Service = "https://plc.directory"
	}

	if args.H == nil {
		args.H = util.RobustHTTPClient()
	}

	rk, err := atcrypto.ParsePrivateBytesK256([]byte(args.RotationKey))
	if err != nil {
		return nil, err
	}

	return &Client{
		h:              args.H,
		service:        args.Service,
		rotationKey:    rk,
		pdsHostname:    args.PdsHostname,
		serviceAuthKey: args.ServiceAuthKey,
	}, nil
}

func (c *Client) CreateDID(sigkey *atcrypto.PrivateKeyK256, recovery string, handle string) (string, *Operation, error) {
	creds, err := c.CreateDidCredentials(sigkey, recovery, handle)
	if err != nil {
		return "", nil, err
	}

	op := Operation{
		Type:                "plc_operation",
		VerificationMethods: creds.VerificationMethods,
		RotationKeys:        creds.RotationKeys,
		AlsoKnownAs:         creds.AlsoKnownAs,
		Services:            creds.Services,
		Prev:                nil,
	}

	if err := c.SignOp(&op); err != nil {
		return "", nil, err
	}

	did, err := DidFromOp(&op)
	if err != nil {
		return "", nil, err
	}

	return did, &op, nil
}

func (c *Client) CreateDidCredentials(sigkey *atcrypto.PrivateKeyK256, recovery string, handle string) (*DidCredentials, error) {
	pubsigkey, err := sigkey.PublicKey()
	if err != nil {
		return nil, err
	}
	return c.createDidCredentialsFromPublicKey(pubsigkey, recovery, handle)
}

// CreateDidCredentialsFromPublicKey builds DID credentials from a public key.
func (c *Client) CreateDidCredentialsFromPublicKey(pubsigkey atcrypto.PublicKey, recovery string, handle string) (*DidCredentials, error) {
	return c.createDidCredentialsFromPublicKey(pubsigkey, recovery, handle)
}

func (c *Client) createDidCredentialsFromPublicKey(pubsigkey atcrypto.PublicKey, recovery string, handle string) (*DidCredentials, error) {
	pubrotkey, err := c.rotationKey.PublicKey()
	if err != nil {
		return nil, err
	}

	// Put the recovery key first when present.
	rotationKeys := []string{pubrotkey.DIDKey()}
	if recovery != "" {
		rotationKeys = func(recovery string) []string {
			newRotationKeys := []string{recovery}
			newRotationKeys = append(newRotationKeys, rotationKeys...)
			return newRotationKeys
		}(recovery)
	}

	// Derive the service-auth public key for the atproto_service verification method.
	serviceAuthPub, err := c.serviceAuthKey.PublicKey()
	if err != nil {
		return nil, err
	}

	creds := DidCredentials{
		VerificationMethods: map[string]string{
			"atproto":         pubsigkey.DIDKey(),
			"atproto_service": serviceAuthPub.DIDKey(),
		},
		RotationKeys: rotationKeys,
		AlsoKnownAs: []string{
			"at://" + handle,
		},
		Services: map[string]identity.OperationService{
			"atproto_pds": {
				Type:     "AtprotoPersonalDataServer",
				Endpoint: "https://" + c.pdsHostname,
			},
		},
	}

	return &creds, nil
}

// RotationKeyBytes returns the raw bytes of the PDS rotation key. This allows
// callers to use the rotation key to sign genesis commits instead of
// generating a throwaway ephemeral key.
func (c *Client) RotationKeyBytes() []byte {
	return c.rotationKey.Bytes()
}

// RotationPrivateKey returns the PDS rotation key as a typed *atcrypto.PrivateKeyK256.
// This allows callers to pass it directly to functions that expect a signing key,
// such as CreateDID, without generating a throwaway ephemeral key.
func (c *Client) RotationPrivateKey() *atcrypto.PrivateKeyK256 {
	return c.rotationKey
}

// SignOp signs a PLC operation with the PDS rotation key. This is the only
// key that can authorise changes to a did:plc document (until the rotation
// key is transferred to the user via supplySigningKey).
func (c *Client) SignOp(op *Operation) error {
	b, err := op.MarshalCBOR()
	if err != nil {
		return err
	}

	sig, err := c.rotationKey.HashAndSign(b)
	if err != nil {
		return err
	}

	op.Sig = base64.RawURLEncoding.EncodeToString(sig)

	return nil
}

func (c *Client) SendOperation(ctx context.Context, did string, op *Operation) error {
	b, err := json.Marshal(op)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.service+"/"+url.QueryEscape(did), bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	req.Header.Add("content-type", "application/json")

	resp, err := c.h.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error sending operation. status code: %d, response: %s", resp.StatusCode, string(b))
	}

	return nil
}

func DidFromOp(op *Operation) (string, error) {
	b, err := op.MarshalCBOR()
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	b32 := strings.ToLower(base32.StdEncoding.EncodeToString(s[:]))
	return "did:plc:" + b32[0:24], nil
}
