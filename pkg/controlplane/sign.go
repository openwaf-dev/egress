// Package controlplane connects the gateway to OpenWAF Cloud as a hosted data-plane node
// (protocol egressnode v1): it polls the signed node configuration document, resolves agents
// from it and reports block events.
package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SignatureScheme is the first line of every signed request input.
const SignatureScheme = "openwaf-node-request/v1"

// Signature headers.
const (
	HeaderNodeID    = "X-OpenWAF-Node-ID"
	HeaderNodeKeyID = "X-OpenWAF-Node-Key-ID"
	HeaderTimestamp = "X-OpenWAF-Timestamp"
	HeaderNonce     = "X-OpenWAF-Nonce"
	HeaderSignature = "X-OpenWAF-Signature"
)

var reNodeID = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// ValidNodeID reports whether id is an acceptable node id.
func ValidNodeID(id string) bool { return reNodeID.MatchString(id) }

// KeyID returns the node key id: the first 16 hex characters of SHA-256 of the raw public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// PublicKeyBase64 returns the raw 32-byte public key in standard base64, the form the
// operator registers with POST /v1/egress/nodes.
func PublicKeyBase64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// SigningInput builds the exact bytes signed for a request.
func SigningInput(method, escapedPath, rawQuery, timestamp, nonce, nodeID, keyID string, body []byte) []byte {
	if escapedPath == "" {
		escapedPath = "/"
	}
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{
		SignatureScheme, method, escapedPath, rawQuery, timestamp, nonce, nodeID, keyID, hex.EncodeToString(sum[:]),
	}, "\n"))
}

// Signer signs control-plane requests as one node.
type Signer struct {
	nodeID string
	keyID  string
	key    ed25519.PrivateKey
	now    func() time.Time
}

// NewSigner returns a Signer for nodeID with its ed25519 private key.
func NewSigner(nodeID string, key ed25519.PrivateKey) (*Signer, error) {
	if !ValidNodeID(nodeID) {
		return nil, fmt.Errorf("invalid node id %q (want ^[a-z0-9][a-z0-9.-]{0,62}$)", nodeID)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key")
	}
	pub := key.Public().(ed25519.PublicKey)
	return &Signer{nodeID: nodeID, keyID: KeyID(pub), key: key, now: time.Now}, nil
}

// NodeID returns the node id requests are signed for.
func (s *Signer) NodeID() string { return s.nodeID }

// KeyID returns the node key id sent with each request.
func (s *Signer) KeyID() string { return s.keyID }

// Sign sets the signature headers on req, whose body is body (nil for none). A fresh
// timestamp and nonce are used on every call, so a retried request must be signed again.
func (s *Signer) Sign(req *http.Request, body []byte) error {
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	nonce := hex.EncodeToString(n[:])
	ts := strconv.FormatInt(s.now().Unix(), 10)
	input := SigningInput(req.Method, req.URL.EscapedPath(), req.URL.RawQuery, ts, nonce, s.nodeID, s.keyID, body)
	req.Header.Set(HeaderNodeID, s.nodeID)
	req.Header.Set(HeaderNodeKeyID, s.keyID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, "ed25519="+base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, input)))
	return nil
}

// ParsePrivateKeyPEM parses a PKCS#8 "PRIVATE KEY" PEM block holding an ed25519 key.
func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PKCS#8 PRIVATE KEY PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#8 key: %w", err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("node key is not an ed25519 key")
	}
	return key, nil
}

// LoadPrivateKey reads a PKCS#8 PEM ed25519 private key file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading node key: %w", err)
	}
	return ParsePrivateKeyPEM(data)
}

// GenerateKeyFile writes a new ed25519 private key as PKCS#8 PEM to path (mode 0600; an
// existing file is never overwritten) and returns the public key.
func GenerateKeyFile(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	return pub, nil
}
