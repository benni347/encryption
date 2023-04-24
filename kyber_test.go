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

func TestEncryptKyber(t *testing.T) {
	_, publicKey, _ := GenerateKyberKeyPair()
	ciphertext, sharedSecret, err := EncryptKyber(publicKey)
	if err != nil {
		t.Errorf("Error encrypting with Kyber: %v", err)
	}

	if len(ciphertext) != kyberk2so.Kyber1024CTBytes {
		t.Errorf("Ciphertext has incorrect length: got %d, want %d", len(ciphertext), kyberk2so.Kyber1024CTBytes)
	}
	if len(sharedSecret) != kyberk2so.KyberSSBytes {
		t.Errorf("Shared secret has incorrect length: got %d, want %d", len(sharedSecret), kyberk2so.KyberSSBytes)
	}
}

func TestDecryptKyber(t *testing.T) {
	_, publicKey, _ := GenerateKyberKeyPair()
	ciphertext, _, _ := EncryptKyber(publicKey)
	privateKey, _, _ := GenerateKyberKeyPair()
	sharedSecret, err := DecryptKyber(ciphertext, privateKey)
	if err != nil {
		t.Errorf("Error decrypting with Kyber: %v", err)
	}

	if len(sharedSecret) != kyberk2so.KyberSSBytes {
		t.Errorf("Shared secret has incorrect length: got %d, want %d", len(sharedSecret), kyberk2so.KyberSSBytes)
	}
}
