package encryption

import "testing"
import kyberk2so "github.com/symbolicsoft/kyber-k2so"

func TestGenerateKyberKeyPair(t *testing.T) {
	privateKey, publicKey, err := GenerateKyberKeyPair()
	if err != nil {
		t.Errorf("Error generating Kyber key pair: %v", err)
	}
	if len(privateKey) != kyberk2so.Kyber1024SKBytes {
		t.Errorf("Private key has incorrect length: got %d, want %d", len(privateKey), kyberk2so.Kyber1024SKBytes)
	}
	if len(publicKey) != kyberk2so.Kyber1024PKBytes {
		t.Errorf("Public key has incorrect length: got %d, want %d", len(publicKey), kyberk2so.Kyber1024PKBytes)
	}
}
