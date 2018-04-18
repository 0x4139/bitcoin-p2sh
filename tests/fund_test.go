package tests

import (
	"reflect"
	"testing"
	"github.com/0x4139/bitcoin-p2sh"
	"github.com/0x4139/bitcoin-p2sh/btc"
)

func TestGenerateFund(t *testing.T) {
	btc.SetFixedNonce = true //SetFixedNonce set to true to get repeatable signatures with a fixed nonce for testing.
	{
		testPrivateKeyWIF := "5JJyqG4bb15zqi7fTA4b227aUxQhBo1Ux6qX69ngeXYLr7fk2hs"
		testInputTx := "3ad337270ac0ba14fbce812291b7d95338c878709ea8123a4d88c3c29efbc6ac"
		testAmount := 65600
		testP2SHDestination := "347N1Thc213QqfYCz3PZkjoJpNv5b14kBd"
		testFinalTransanctionHex := "0100000001acc6fb9ec2c3884d3a12a89e7078c83853d9b7912281cefb14bac00a2737d33a000000008b483045022100fb244ac83b257f4233920077819dfa5203a11cd330c58a37c984699bc8048e9102200caca5b3772022a5cb5ce8e31f644da4e27e2c4f121cfd9b5291e3bccf7017d701410431393af9984375830971ab5d3094c6a7d02db3568b2b06212a7090094549701bbb9e84d9477451acc42638963635899ce91bacb451a1bb6da73ddfbcf596bddfffffffff01400001000000000017a9141a8b0026343166625c7475f01e48b5ede8c0252e8700000000"

		finalTransactionHex, err := btcp2sh.GenerateFund(testPrivateKeyWIF, testInputTx, testAmount, testP2SHDestination)
		if err != nil {
			t.Fatalf("error while generating fund %s", err.Error())
		}
		if finalTransactionHex != testFinalTransanctionHex {
			CompareError(t, "Generated funding transaction different from expected transaction.", testFinalTransanctionHex, finalTransactionHex)
		}
	}
	{
		testPrivateKeyWIF := "5KfWTqGjHY4e912qbhKow8VToKrgaHT7d7szxUCAepmV2nUn9k9"
		testInputTx := "2648867c648fa66f3c81f0d75c10577250e2568490741da6928e2fb8bad9479f"
		testAmount := 135600
		testP2SHDestination := "3ErDPiDD7AsJDqKkayMA39iLJevTjDCjUa"
		testFinalTransanctionHex := "01000000019f47d9bab82f8e92a61d74908456e2507257105cd7f0813c6fa68f647c864826000000008b4830450221008b0163ee36e011485405ff23ab7844a4d0adccb488e7fde8513c01b11a18c9b40220278944564d3476b2634322af5f271b119700e8ff55c977a3664959af71cb77d2014104ff4c2ce7513a6c896ebfaaa4ae52cea35374e0eac90ccb8f4e5fa14b8322e2bae4c65116c7af2ba6a82831e48c451fc29a66d49c24757130ebf07c142bbcbe75ffffffff01b01102000000000017a9149056f3c2a8cbd11340fa2ee4736dea1d298c9d118700000000"

		finalTransactionHex, err := btcp2sh.GenerateFund(testPrivateKeyWIF, testInputTx, testAmount, testP2SHDestination)
		if err != nil {
			t.Fatalf("error while generating fund %s", err.Error())
		}
		if finalTransactionHex != testFinalTransanctionHex {
			CompareError(t, "Generated funding transaction different from expected transaction.", testFinalTransanctionHex, finalTransactionHex)
		}
	}
	{
		testPrivateKeyWIF := "5KDTZxSx6b68m2bWaUKaHdnDPEhcRE3uJRnfFvHKkQi9Uw8cw5G"
		testInputTx := "d073ced3663e40d4917c8fa5858b5cc4c95c4a7e5d3b33512ba94824da8c7b50"
		testAmount := 195600
		testP2SHDestination := "34wgSuG9qtaNEV4MGye9UJcffcFTxnmXSC"
		testFinalTransanctionHex := "0100000001507b8cda2448a92b51333b5d7e4a5cc9c45c8b85a58f7c91d4403e66d3ce73d0000000008a47304402207db305bede3534d7b8d2d90a62810e407252ce47b2a726e01b8ca7cde3466401022009bd98a9e281fa930f0fcfe1545a70139fe599d9f1a93223ab29717caa19f90f014104d95cf578183f346117b9743722bb6df93e1c62990824a1fc6645fd3dee45fa7ea5f164da7b518c3fd08a623664410df5a3b5f6ef1c5a285e834fd57c5a24a41effffffff0110fc02000000000017a91423ae5bc99220a608aefb8455cdf7f43bfdbae67d8700000000"

		finalTransactionHex, err := btcp2sh.GenerateFund(testPrivateKeyWIF, testInputTx, testAmount, testP2SHDestination)
		if err != nil {
			t.Fatalf("error while generating fund %s", err.Error())
		}
		if finalTransactionHex != testFinalTransanctionHex {
			CompareError(t, "Generated funding transaction different from expected transaction.", testFinalTransanctionHex, finalTransactionHex)
		}
	}
}

func TestSignP2PKHTransaction(t *testing.T) {
	{
		testPrivateKey := []byte{20, 175, 46, 68, 8, 91, 132, 129, 57, 230, 158, 54, 186, 115, 191, 245, 121, 11, 108, 224, 125, 96, 99, 40, 11, 156, 199, 158, 55, 199, 110, 229}
		testInputTx := "3ad337270ac0ba14fbce812291b7d95338c878709ea8123a4d88c3c29efbc6ac"
		testAmount := 65600
		testScriptPubKey := []byte{169, 20, 26, 139, 0, 38, 52, 49, 102, 98, 92, 116, 117, 240, 30, 72, 181, 237, 232, 192, 37, 46, 135}
		testRawTx := []byte{1, 0, 0, 0, 1, 172, 198, 251, 158, 194, 195, 136, 77, 58, 18, 168, 158, 112, 120, 200, 56, 83, 217, 183, 145, 34, 129, 206, 251, 20, 186, 192, 10, 39, 55, 211, 58, 0, 0, 0, 0, 25, 118, 169, 20, 146, 3, 228, 122, 22, 247, 153, 222, 208, 53, 50, 227, 228, 82, 96, 111, 220, 82, 0, 126, 136, 172, 255, 255, 255, 255, 1, 64, 0, 1, 0, 0, 0, 0, 0, 23, 169, 20, 26, 139, 0, 38, 52, 49, 102, 98, 92, 116, 117, 240, 30, 72, 181, 237, 232, 192, 37, 46, 135, 0, 0, 0, 0}
		testSignedTx := []byte{1, 0, 0, 0, 1, 172, 198, 251, 158, 194, 195, 136, 77, 58, 18, 168, 158, 112, 120, 200, 56, 83, 217, 183, 145, 34, 129, 206, 251, 20, 186, 192, 10, 39, 55, 211, 58, 0, 0, 0, 0, 139, 72, 48, 69, 2, 33, 0, 178, 94, 76, 190, 47, 250, 176, 232, 225, 177, 102, 156, 123, 205, 101, 110, 13, 80, 77, 140, 60, 204, 32, 41, 56, 199, 205, 21, 5, 182, 219, 59, 2, 32, 13, 40, 107, 255, 198, 63, 144, 23, 75, 231, 227, 220, 125, 89, 77, 162, 201, 201, 51, 111, 100, 111, 123, 252, 166, 15, 5, 213, 15, 20, 181, 189, 1, 65, 4, 31, 94, 124, 86, 83, 22, 214, 220, 255, 68, 144, 37, 212, 245, 109, 15, 125, 62, 188, 143, 134, 225, 79, 52, 23, 48, 146, 180, 180, 96, 82, 136, 25, 21, 66, 0, 130, 244, 216, 175, 215, 116, 19, 108, 62, 70, 207, 235, 149, 85, 153, 140, 40, 104, 214, 135, 189, 203, 127, 61, 30, 232, 22, 147, 255, 255, 255, 255, 1, 64, 0, 1, 0, 0, 0, 0, 0, 23, 169, 20, 26, 139, 0, 38, 52, 49, 102, 98, 92, 116, 117, 240, 30, 72, 181, 237, 232, 192, 37, 46, 135, 0, 0, 0, 0}

		btc.SetFixedNonce = true
		signedTx, err := btcp2sh.SignP2PKHTransaction(testRawTx, testPrivateKey, testScriptPubKey, testInputTx, testAmount)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(testSignedTx, signedTx) {
			CompareError(t, "Generated signature different from expected signature.", testSignedTx, signedTx)
		}
	}
}
