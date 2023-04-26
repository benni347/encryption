package encryption

import (
	"crypto/elliptic"
	"testing"
)

func TestGenerateEccKeyPair(t *testing.T) {
	privateKey, publicKey, err := GenerateECCKeyPair()
	if err != nil {
		t.Errorf("Error generating ECC key pair: %v", err)
	}
	if privateKey == nil {
		t.Fatalf("Private key is nil")
	}
	if publicKey == nil {
		t.Errorf("Public key is nil")
	}
	privateKeyBytes := privateKey.D.Bytes()
	publicKeyBytes := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
	if len(privateKeyBytes) != 32 {
		t.Errorf("Private key has incorrect length: got %d, want %d", len(privateKeyBytes), 32)
	}
	if len(publicKeyBytes) != 65 {
		t.Errorf("Public key has incorrect length: got %d, want %d", len(publicKeyBytes), 65)
	}
}

func TestSignECC(t *testing.T) {
	privateKey, _, _ := GenerateECCKeyPair()
	message := []byte("Hello, world!")
	hash := CalculateHash(message)
	signature, err := SignEcc(privateKey, hash)
	if err != nil {
		t.Errorf("Error signing with ECC: %v", err)
	}
	if len(signature) != 64 {
		t.Errorf("Signature has incorrect length: got %d, want %d", len(signature), 64)
	}
}

func TestVerifyEcc(t *testing.T) {
	privateKey, publicKey, _ := GenerateECCKeyPair()
	message := []byte("Hello, world!")
	hash := CalculateHash(message)
	signature, _ := SignEcc(privateKey, hash)
	verified := VerifyEcc(publicKey, hash, signature)
	if verified != true {
		t.Errorf("Error verifying ECC signature: %v", verified)
	}
}
