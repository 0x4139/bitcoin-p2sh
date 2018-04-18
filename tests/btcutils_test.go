package tests

import (
	"encoding/hex"
	"reflect"
	"testing"
	"github.com/0x4139/bitcoin-p2sh/btc"
	"github.com/0x4139/bitcoin-p2sh/base58"
)

func TestNewPublicKey(t *testing.T) {
	testPrivateKey := []byte{38, 245, 100, 77, 9, 147, 145, 209, 208, 136, 215, 161, 171, 75, 199, 219, 26, 95, 66, 101, 110, 38, 86, 249, 86, 179, 195, 10, 70, 153, 203, 150}
	testPublicKey := []byte{4, 231, 41, 35, 190, 64, 15, 200, 89, 150, 144, 81, 215, 14, 125, 179, 216, 217, 70, 21, 254, 204, 182, 219, 188, 192, 54, 241, 31, 248, 110, 145, 167, 117, 225, 204, 37, 169, 182, 242, 22, 12, 200, 26, 250, 241, 215, 142, 206, 63, 30, 119, 105, 242, 234, 41, 44, 103, 152, 1, 87, 24, 207, 190, 156}

	publicKey, err := btc.NewPublicKey(testPrivateKey)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(testPublicKey, publicKey) {
		CompareError(t, "Public key different from expected key.", testPublicKey, publicKey)
	}
}

func TestHash160(t *testing.T) {
	testHashHex := "51d9ac622c2133ca4aaf58d4a4239526eb42c348"

	hash, err := btc.Hash160([]byte("teststring"))
	if err != nil {
		t.Error(err)
	}
	hashHex := hex.EncodeToString(hash)
	if hashHex != testHashHex {
		CompareError(t, "Deterministic hash RIPEMD160(SHA256(data)) different from expected hash.", testHashHex, hashHex)
	}
}

func TestNewMOfNRedeemScript(t *testing.T) {
	testPublicKeyStrings := []string{
		"0446f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695ce9",
		"04704e19d4fc234a42d707d41053c87011f990b564949532d72cab009e136bd60d7d0602f925fce79da77c0dfef4a49c6f44bd0540faef548e37557d74b36da124",
		"04b75a8cb10fd3f1785addbafdb41b409ecd6ffd50d5ad71d8a3cdc5503bcb35d3d13cdf23f6d0eb6ab88446276e2ba5b92d8786da7e5c0fb63aafb62f87443d28",
	}
	testM := 2
	testN := 3
	testRedeemScriptHex := "52410446f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695ce94104704e19d4fc234a42d707d41053c87011f990b564949532d72cab009e136bd60d7d0602f925fce79da77c0dfef4a49c6f44bd0540faef548e37557d74b36da1244104b75a8cb10fd3f1785addbafdb41b409ecd6ffd50d5ad71d8a3cdc5503bcb35d3d13cdf23f6d0eb6ab88446276e2ba5b92d8786da7e5c0fb63aafb62f87443d2853ae"

	publicKeys := make([][]byte, len(testPublicKeyStrings))
	for i, publicKeyString := range testPublicKeyStrings {
		publicKeys[i], _ = hex.DecodeString(publicKeyString) //Get private keys as slice of raw bytes
	}
	redeemScript, err := btc.NewMOfNRedeemScript(testM, testN, publicKeys)
	if err != nil {
		t.Error(err)
	}
	redeemScriptHex := hex.EncodeToString(redeemScript)
	if redeemScriptHex != testRedeemScriptHex {
		CompareError(t, "M-of-N redeem script different from expected script.", testRedeemScriptHex, redeemScriptHex)
	}
}

func TestCheckPublicKeyIsValid(t *testing.T) {
	invalidPublicKeyStrings := []string{
		"",                                                                                                                                   //empty key
		"0446f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695c",   //wrong length key
		"0346f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695ce9", //wrong prefix key
	}
	for _, publicKeyString := range invalidPublicKeyStrings {
		publicKey, _ := hex.DecodeString(publicKeyString)
		if btc.CheckPublicKeyIsValid(publicKey) == nil {
			t.Error("CheckPublicKeyIsValid accepting invalids public keys as valid.")
		}
	}
}

func TestNewP2SHScriptPubKey(t *testing.T) {
	testRedeemScriptHashString := "51d9ac622c2133ca4aaf58d4a4239526eb42c348"
	testScriptPubKeyHex := "a91451d9ac622c2133ca4aaf58d4a4239526eb42c34887"

	redeemScriptHash, _ := hex.DecodeString(testRedeemScriptHashString)
	scriptPubKey, err := btc.NewP2SHScriptPubKey(redeemScriptHash)
	if err != nil {
		t.Error(err)
	}
	scriptPubKeyHex := hex.EncodeToString(scriptPubKey)
	if scriptPubKeyHex != testScriptPubKeyHex {
		CompareError(t, "P2SH scriptPubKey different from expected script.", testScriptPubKeyHex, scriptPubKeyHex)
	}
}

func TestNewP2PKHScriptPubKey(t *testing.T) {
	testPublicAddressString := "13LSqJeZBpqLHzmLkJ5mvRHiM11waShFUP"
	testPublicKeyHash := base58.Decode(testPublicAddressString)
	testScriptPubKeyHex := "76a914199db810a3c8ae5e55c0432d2b72e55b0634f79088ac"

	scriptPubKey, err := btc.NewP2PKHScriptPubKey(testPublicKeyHash)
	if err != nil {
		t.Error(err)
	}
	scriptPubKeyHex := hex.EncodeToString(scriptPubKey)
	if scriptPubKeyHex != testScriptPubKeyHex {
		CompareError(t, "P2PKH scriptPubKey different from expected script.", testScriptPubKeyHex, scriptPubKeyHex)
	}
}

func TestNewRawTransaction(t *testing.T) {
	testInputTx := "3ad337270ac0ba14fbce812291b7d95338c878709ea8123a4d88c3c29efbc6ac"
	testAmount := 65600
	testScriptSig := []byte{118, 169, 20, 146, 3, 228, 122, 22, 247, 153, 222, 208, 53, 50, 227, 228, 82, 96, 111, 220, 82, 0, 126, 136, 172}
	testScriptPubKey := []byte{169, 20, 26, 139, 0, 38, 52, 49, 102, 98, 92, 116, 117, 240, 30, 72, 181, 237, 232, 192, 37, 46, 135}
	testRawTx := []byte{1, 0, 0, 0, 1, 172, 198, 251, 158, 194, 195, 136, 77, 58, 18, 168, 158, 112, 120, 200, 56, 83, 217, 183, 145, 34, 129, 206, 251, 20, 186, 192, 10, 39, 55, 211, 58, 0, 0, 0, 0, 25, 118, 169, 20, 146, 3, 228, 122, 22, 247, 153, 222, 208, 53, 50, 227, 228, 82, 96, 111, 220, 82, 0, 126, 136, 172, 255, 255, 255, 255, 1, 64, 0, 1, 0, 0, 0, 0, 0, 23, 169, 20, 26, 139, 0, 38, 52, 49, 102, 98, 92, 116, 117, 240, 30, 72, 181, 237, 232, 192, 37, 46, 135, 0, 0, 0, 0}

	rawTx, err := btc.NewRawTransaction(testInputTx, testAmount, testScriptSig, testScriptPubKey)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(rawTx, testRawTx) {
		CompareError(t, "Raw transaction different from expected transaction.", testRawTx, rawTx)
	}
}

func TestNewSignature(t *testing.T) {
	testRawTx := []byte{1, 0, 0, 0, 1, 172, 198, 251, 158, 194, 195, 136, 77, 58, 18, 168, 158, 112, 120, 200, 56, 83, 217, 183, 145, 34, 129, 206, 251, 20, 186, 192, 10, 39, 55, 211, 58, 0, 0, 0, 0, 25, 118, 169, 20, 146, 3, 228, 122, 22, 247, 153, 222, 208, 53, 50, 227, 228, 82, 96, 111, 220, 82, 0, 126, 136, 172, 255, 255, 255, 255, 1, 64, 0, 1, 0, 0, 0, 0, 0, 23, 169, 20, 26, 139, 0, 38, 52, 49, 102, 98, 92, 116, 117, 240, 30, 72, 181, 237, 232, 192, 37, 46, 135, 0, 0, 0, 0}
	testPrivateKey := []byte{20, 175, 46, 68, 8, 91, 132, 129, 57, 230, 158, 54, 186, 115, 191, 245, 121, 11, 108, 224, 125, 96, 99, 40, 11, 156, 199, 158, 55, 199, 110, 229}
	testSignature := []byte{48, 69, 2, 33, 0, 178, 94, 76, 190, 47, 250, 176, 232, 225, 177, 102, 156, 123, 205, 101, 110, 13, 80, 77, 140, 60, 204, 32, 41, 56, 199, 205, 21, 5, 182, 219, 59, 2, 32, 13, 40, 107, 255, 198, 63, 144, 23, 75, 231, 227, 220, 125, 89, 77, 162, 201, 201, 51, 111, 100, 111, 123, 252, 166, 15, 5, 213, 15, 20, 181, 189}

	btc.SetFixedNonce = true //Use testing-only setting to fix nonce at zero bytes, so we can get repeatability in testing
	signature, err := btc.NewSignature(testRawTx, testPrivateKey)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(testSignature, signature) {
		CompareError(t, "ECDSA signature different from expected signature.", testSignature, signature)
	}
}
