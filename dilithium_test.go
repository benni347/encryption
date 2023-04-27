package encryption

import (
	"bytes"
	"testing"
)

func TestDilithiumFunction(t *testing.T) {
	modes := []string{"Dilithium5", "Dilithium5-AES"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			// Test GenerateDilithiumKeyPair
			pubKey, privKey, err := GenerateDilithiumKeyPair(mode)
			if err != nil {
				t.Fatalf("GenerateDilithiumKeyPair failed: %v", err)
			}

			// Test PackDilithiumKeys and UnpackDilithiumKeys
			packedPubKey, packedPrivKey := PackDilithiumKeys(pubKey, privKey)
			unpackedPubKey, unpackedPrivKey := UnpackDilithiumKeys(
				mode,
				packedPubKey,
				packedPrivKey,
			)

			if !bytes.Equal(pubKey.Bytes(), unpackedPubKey.Bytes()) {
				t.Error("Unpacked public key does not match the original")
			}
			if !bytes.Equal(privKey.Bytes(), unpackedPrivKey.Bytes()) {
				t.Error("Unpacked private key does not match the original")
			}

			// Test SignDilithium
			msg := []byte("test message")
			signature, _, err := SignDilithium(privKey, msg, mode)
			if err != nil {
				t.Fatalf("SignDilithium failed: %v", err)
			}

			// Test VerifyDilithium
			valid, err := VerifyDilithium(pubKey, msg, signature, mode)
			if err != nil {
				t.Fatalf("VerifyDilithium failed: %v", err)
			}
			if !valid {
				t.Error("Signature verification failed")
			}
		})
	}
}
