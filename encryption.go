package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/dilithium"
	kyberk2so "github.com/symbolicsoft/kyber-k2so"
	"golang.org/x/crypto/blake2b"
)

func GenerateECCKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, nil
}

func SignEcc(privateKey *ecdsa.PrivateKey, messageHash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, messageHash)
	if err != nil {
		return nil, err
	}

	curveBits := privateKey.PublicKey.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8

	signature := make([]byte, keyBytes*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(signature[keyBytes-len(rBytes):], rBytes)
	copy(signature[keyBytes*2-len(sBytes):], sBytes)

	return signature, nil
}

func VerifyEcc(publicKey *ecdsa.PublicKey, messageHash, signature []byte) bool {
	curveBits := publicKey.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8

	r := new(big.Int).SetBytes(signature[:keyBytes])
	s := new(big.Int).SetBytes(signature[keyBytes:])

	return ecdsa.Verify(publicKey, messageHash, r, s)
}

// From here to the lines which is a comment which contains --- the functions used are under the BSD3-Clause license.
// https://pkg.go.dev/github.com/cloudflare/circl/sign/dilithium

func GenerateDilithiumKeyPair(modeName string) (dilithium.PublicKey, dilithium.PrivateKey, error) {
	mode := dilithium.ModeByName(modeName)
	if mode == nil {
		return nil, nil, fmt.Errorf("mode not supported")
	}

	publicKey, privateKey, err := mode.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key pair: %v", err)
	}

	return publicKey, privateKey, nil
}

func PackDilithiumKeys(
	publicKey dilithium.PublicKey,
	privateKey dilithium.PrivateKey,
) ([]byte, []byte) {
	return publicKey.Bytes(), privateKey.Bytes()
}

func UnpackDilithiumKeys(
	modeName string,
	packedPublicKey []byte,
	packedPrivateKey []byte,
) (dilithium.PublicKey, dilithium.PrivateKey) {
	mode := dilithium.ModeByName(modeName)

	return mode.PublicKeyFromBytes(packedPublicKey), mode.PrivateKeyFromBytes(packedPrivateKey)
}

func SignDilithium(
	privateKey dilithium.PrivateKey,
	msg []byte,
	modeName string,
) ([]byte, int, error) {
	mode := dilithium.ModeByName(modeName)
	if mode == nil {
		return nil, -1, fmt.Errorf("mode not supported")
	}

	signatureSize := mode.SignatureSize()

	return mode.Sign(privateKey, msg), signatureSize, nil
}

func VerifyDilithium(
	publicKey dilithium.PublicKey,
	msg []byte,
	signature []byte,
	modeName string,
) (bool, error) {
	mode := dilithium.ModeByName(modeName)
	if mode == nil {
		return false, fmt.Errorf("mode not supported")
	}

	return mode.Verify(publicKey, msg, signature), nil
}

// ---

func PrintError(message string, err error) {
	fmt.Printf("\033[1mERROR:\033[0m %s: %v\n", message, err)
}

func PrintInfo(message string, verbose bool) {
	if verbose {
		fmt.Printf("\033[1m%s\033[0m: %s\n", "INFO", message)
	}
}

func GenerateKyberKeyPair() ([kyberk2so.Kyber1024SKBytes]byte, [kyberk2so.Kyber1024PKBytes]byte, error) {
	privateKey, publicKey, err := kyberk2so.KemKeypair1024()
	if err != nil {
		PrintError("During the Creation of the Kyber KeyPair", err)
		return privateKey, publicKey, err
	}

	return privateKey, publicKey, nil
}

func EncryptKyber(
	publicKey *[kyberk2so.Kyber1024PKBytes]byte,
) ([kyberk2so.Kyber1024CTBytes]byte, [kyberk2so.KyberSSBytes]byte, error) {
	return kyberk2so.KemEncrypt1024(*publicKey)
}

func DecryptKyber(
	ciphertext *[kyberk2so.Kyber1024CTBytes]byte,
	privateKey *[kyberk2so.Kyber1024SKBytes]byte,
) ([kyberk2so.KyberSSBytes]byte, error) {
	return kyberk2so.KemDecrypt1024(*ciphertext, *privateKey)
}

func CalculateHash(message []byte) []byte {
	hash, err := blake2b.New512(nil)
	if err != nil {
		fmt.Printf("Error creating hash: %v\n", err)
		return nil
	}
	hash.Write(message)
	return hash.Sum(nil)
}

/*
func main() {
	var args struct {
		Verbose bool `arg:"-v" help:"Prints all debug messages."`
	}
	arg.MustParse(&args)

	msg := []byte("Profil. Berufsvorbereitung")

	curve := elliptic.P256()
	privateKeyEcc, publicKeyEcc, err := generateECCKeyPair(curve)
	if err != nil {
		printError("Generating key pair for ecc the error is", err)
		return
	}

	hash := calculateHash(msg)
	signature, err := signEcc(privateKeyEcc, hash)
	if err != nil {
		printError("During signing the message with ECC the error is", err)
		return
	}

	valid := verifyEcc(publicKeyEcc, hash, signature)
	if valid {
		printInfo("Signature is valid!", args.Verbose)
	} else {
		printInfo("Signature is not valid!", args.Verbose)
	}

	modeName := "Dilithium5-AES"
	// Generate Dilithium key pair
	publicKey, privateKey, err := generateDilithiumKeyPair(modeName)
	if err != nil {
		printError("During generating Dilithium key pair the error is", err)
		return
	}

	printInfo("CRYSTAl-Dilithium Public Key: "+hex.EncodeToString(publicKey.Bytes()), args.Verbose)

	// Pack and unpack Dilithium keys
	packedPublicKey, packedPrivateKey := packDilithiumKeys(publicKey, privateKey)
	publicKey2, privateKey2 := unpackDilithiumKeys(modeName, packedPublicKey, packedPrivateKey)

	// Sign and verify with Dilithium keys
	signature, signatureLength, err := signDilithium(privateKey2, msg, modeName)
	if err != nil {
		printError("During signing the message with Dilithium the error is", err)
	}

	printInfo(fmt.Sprintf("Signature length is: %d", signatureLength), args.Verbose)

	printInfo("CRYSTAl-Dilithium Signature: "+hex.EncodeToString(signature), args.Verbose)

	valid, err = verifyDilithium(publicKey2, msg, signature, modeName)
	if err != nil {
		printError("During verifying the message with Dilithium the error is", err)
	}

	if valid {
		printInfo("CRYSTAl-Dilithium Signature is valid!", args.Verbose)
	} else {
		printInfo("CRYSTAl-Dilithium Signature is not valid!", args.Verbose)
	}
}

*/
