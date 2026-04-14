package agentutil

import (
	"bytes"
	"errors"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ReadOnlyAgent struct {
	mu      sync.RWMutex
	signers []ssh.Signer
	comment string
}

func NewReadOnlyAgent(comment string, signers ...ssh.Signer) *ReadOnlyAgent {
	return &ReadOnlyAgent{signers: signers, comment: comment}
}

func (a *ReadOnlyAgent) List() ([]*agent.Key, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	keys := make([]*agent.Key, 0, len(a.signers))
	for _, signer := range a.signers {
		pk := signer.PublicKey()
		keys = append(keys, &agent.Key{
			Format:  pk.Type(),
			Blob:    pk.Marshal(),
			Comment: a.comment,
		})
	}
	return keys, nil
}

func (a *ReadOnlyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, signer := range a.signers {
		if samePublicKey(key, signer.PublicKey()) {
			return signer.Sign(nil, data)
		}
	}
	return nil, errors.New("signer not found")
}

func (a *ReadOnlyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, signer := range a.signers {
		if !samePublicKey(key, signer.PublicKey()) {
			continue
		}
		if algoSigner, ok := signer.(ssh.AlgorithmSigner); ok {
			algo := signer.PublicKey().Type()
			if flags == agent.SignatureFlagRsaSha256 {
				algo = ssh.SigAlgoRSASHA2256
			} else if flags == agent.SignatureFlagRsaSha512 {
				algo = ssh.SigAlgoRSASHA2512
			}
			return algoSigner.SignWithAlgorithm(nil, data, algo)
		}
		return signer.Sign(nil, data)
	}
	return nil, errors.New("signer not found")
}

func (a *ReadOnlyAgent) Add(_ agent.AddedKey) error   { return errors.New("read-only agent") }
func (a *ReadOnlyAgent) Remove(_ ssh.PublicKey) error { return errors.New("read-only agent") }
func (a *ReadOnlyAgent) RemoveAll() error             { return errors.New("read-only agent") }
func (a *ReadOnlyAgent) Lock(_ []byte) error          { return errors.New("read-only agent") }
func (a *ReadOnlyAgent) Unlock(_ []byte) error        { return errors.New("read-only agent") }
func (a *ReadOnlyAgent) Extension(_, _ string) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func (a *ReadOnlyAgent) Signers() ([]ssh.Signer, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.signers, nil
}

func samePublicKey(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}
