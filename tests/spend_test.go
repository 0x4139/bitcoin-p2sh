package tests

import (
	"reflect"
	"testing"
	"github.com/0x4139/bitcoin-p2sh"
	"github.com/0x4139/bitcoin-p2sh/btc"
)

func TestGenerateSpend(t *testing.T) {
	btc.SetFixedNonce = true
	{
		//5-of-7 spending multisig test
		testPrivateKeys := "5HrL5AUs1WHYPxUmb7YwCYD448PixCH3epsf7meQg1tshQv8dbM,5JQLb8Hw69xZ9ybCAqUvDqdjyybSpcRFJCo921hZQgTX9eoBjgY,5K3AZzU3PbPQ2XmKSrnCuCvKVNebeG3VzVEjzMiszwpXT7y2qX1,5JcF9u4mxWVMHRHLZdQqDFuvv7izUkeTsmNiYdvEYyu5HfM2ju2,5K7DaqVHmZCv5jvUq8Ga9L9NoiiL4LUvpgUw4HwnvnFghgFBqLD"
		testDestination := "1DJrhysUSzjNhP1GYJkgQkkEtCTgnnEWXi"
		testRedeemScript := "554104c22e4293d1d462eef905e592ad4aff332aa52c3415b824cd85cf594258d92c836fe797187bc2459261e0597c4ef351c5d0c26f7a60165221e221a38e448ad08c4104bb28684dfe23852a7c276827dd448c955007e7ccbfacbf536e13f1097b30430ebec5af0bc001e50d3f0e796d52ba43e3c07337bfed2a842659d51632f2b21d2841048f8551173f8e7414ff0e144899b3f70accd957e6913f5cf877bd576f6c16f0aa67fb9b96e0df10562b4f7ba4060acd22f142329ff83f1d96e27f4e4394adeda24104aa81def7dda6a4f40be2f3287ee3423f255b07965104a7888df075217c9ee5b3e9e2e70115d43bfecbff8062f8289f5cab3d0ebd96c9f55c85f6147ff3a5e9494104493aa5f89ec34184a235b2c9f608eade1634636f94f64b59419875e15cb86a6d8c708a9d5eda3304cb983b2325a57af881ed75f28179f5f263d7758039b68d894104dc284f749208d7fec57937bc5e72187b064df7d29b7aa82cae273e9a1c91beae9c510e0fd632a3db272c67db04061ea761d1ed91fdb8ab07e354047c64ce405d41042fc7796f54dd482db20f1bcce584f930ae74d5f27fc8336e2701bd0243d681281810c57e079947ebdfdfc8860ed34b0ba32db82a85249adc7c64ab547d48af6457ae"
		testInputTx := "c2e036e044445c3d699976b5ec8ef3419c228e3b150a48706ac49cad5b7669da"
		testAmount := 145600
		testFinalTransactionHex := "0100000001da69765bad9cc46a70480a153b8e229c41f38eecb57699693d5c4444e036e0c200000000fd4003004730440220444c3f5926d2942799fa3ccc03ac539be4af88e4180138181d247bf5e9c15fef022044d3f1a69e755ca45c8f3d592a603b47e3336716fe3eeeb8492d17c7fd7c6c3a0147304402205b61381a7dffb08084459b7eac64aabb03f44b998b3e232b2045ed8ba52e6f7202202fd27f3143ef335406a9472ed07d09f7554b30146a66499c6ab814f770fff0fb01483045022100cdda24d8bd8eb3515d4e130ca42df09e1cbf8c56c108c4557a67563c2d57160f02206569a950c3718b6f221354385184a143b154e7e57b5c75cc18cd323ab9de894001483045022100da7d42eb8b441e3868e7ff664381eb1d812f635b4fa580c4291a9a4eb647130d02201e99159e0ce585e652f8bef8b1c85a557b4557f7cda09c71c763d550b8f71afa01483045022100cab3ba0d10e91e1539be5e70e16901980bfe0cccd5fbe7a9cb731a977799eb0002201ee0200e952c2a6c05469805bc0b1603c972530b66152b8323819618385229e9014dd101554104c22e4293d1d462eef905e592ad4aff332aa52c3415b824cd85cf594258d92c836fe797187bc2459261e0597c4ef351c5d0c26f7a60165221e221a38e448ad08c4104bb28684dfe23852a7c276827dd448c955007e7ccbfacbf536e13f1097b30430ebec5af0bc001e50d3f0e796d52ba43e3c07337bfed2a842659d51632f2b21d2841048f8551173f8e7414ff0e144899b3f70accd957e6913f5cf877bd576f6c16f0aa67fb9b96e0df10562b4f7ba4060acd22f142329ff83f1d96e27f4e4394adeda24104aa81def7dda6a4f40be2f3287ee3423f255b07965104a7888df075217c9ee5b3e9e2e70115d43bfecbff8062f8289f5cab3d0ebd96c9f55c85f6147ff3a5e9494104493aa5f89ec34184a235b2c9f608eade1634636f94f64b59419875e15cb86a6d8c708a9d5eda3304cb983b2325a57af881ed75f28179f5f263d7758039b68d894104dc284f749208d7fec57937bc5e72187b064df7d29b7aa82cae273e9a1c91beae9c510e0fd632a3db272c67db04061ea761d1ed91fdb8ab07e354047c64ce405d41042fc7796f54dd482db20f1bcce584f930ae74d5f27fc8336e2701bd0243d681281810c57e079947ebdfdfc8860ed34b0ba32db82a85249adc7c64ab547d48af6457aeffffffff01c0380200000000001976a914870212de342646df8eb8874964f78ae2929f063e88ac00000000"

		finalTransactionHex, err := btcp2sh.GenerateSpend(testPrivateKeys, testDestination, testRedeemScript, testInputTx, testAmount)
		if err != nil {
			t.Fatalf("Error while generating spend transaction %s", err.Error())
		}
		if testFinalTransactionHex != finalTransactionHex {
			CompareError(t, "Generated spend transaction different from expected transaction.", testFinalTransactionHex, finalTransactionHex)
		}
	}
	{
		//7-of-7 spending multisig test
		testPrivateKeys := "5HzzPqdbfmGLFZVYYYpr9Z1uU2D4Xxigik8A6U3zFTdDLtYof4b,5JaNjcNtnmQRSqvRQLMMjRvxYVpKXVs6ME9hZxH8VeGPTG9VVoH,5K23G9Tf7HpcP1gnNuXRUBREj81KGqF2L5dU1HeHX9qtii1kpq5,5J9LHYJQoaip8Aufh2V6oLGwfMcQs88yYY4RBqHSiSiTqK8qHL5,5JyTXnoFxjfvMC7cgZLhkrjX2UVpeye9H4qJQjr5LrTpfpY1uon,5JFWG8sweJzBrejMpWBHpe4xcmbryNcGbzy3ueFEMM8SppBGxb4,5JrzNyakdSz2SWFeU7RxDCDNL2FtKQjCZXHm1NovR5k1hGfTXFU"
		testDestination := "1EK4KToKVHdz787e26JCQuSTtnPAvJZRC5"
		testRedeemScript := "57410446f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695ce94104704e19d4fc234a42d707d41053c87011f990b564949532d72cab009e136bd60d7d0602f925fce79da77c0dfef4a49c6f44bd0540faef548e37557d74b36da1244104b75a8cb10fd3f1785addbafdb41b409ecd6ffd50d5ad71d8a3cdc5503bcb35d3d13cdf23f6d0eb6ab88446276e2ba5b92d8786da7e5c0fb63aafb62f87443d284104033a82ccb1291bbc27cf541c6c487c213f25db85c620ecb9cbb76ca461ef13db5a80b90c3ae7d2a5e47623cdf520a2586cac7e41f779103a71a1fe177189781e41045e3b4030be5fd9c4c40e7076bd49f022118d90ae9182de61f3a1adb2ff511c97e8a6a82a9292b01878a18c08b7cd658ebdf80e6ed3f26783b25ba1a52fa9e52d4104c93ceb8f4482e131addc58d3efa0b4967bb7c574de15786d55379cc4a43a61571518abe0f05ebf188bcce9580aa70b3f5b1024ca579819c8810ff79967de3f234104a66f63d2941f0befcfba4b73495a7b99fc7ed28cb41e7934e1de82d852628766dc96ee1e196387a68e7fd8898862c2260f1f2557ac2147af07900695f15abd3f57ae"
		testInputTx := "8462ab27b115d66ea767cc50cb4f1b0070c0200d93d4a6984c374ad6459188f7"
		testAmount := 75600
		testFinalTransactionHex := "0100000001f7889145d64a374c98a6d4930d20c070001b4fcb50cc67a76ed615b127ab628400000000fdd20300483045022100adf8b5493cc2758c4dc7fc25263efbf4e1803734fbbc906298b8fc0909da211802204aa3cf5cdfce75190f4a3998be2b055b303e16e0c0580fb2c7e0fbb69ccd46de01483045022100e0d72aa288d0dfc62cb901fdc7d452fbaee7ca2fb61b40ec7687fcbec37f62ec02203a82efd16c2d900317b2a5fa1568b89db00496622f292e8c0bad1a0a93cd16240147304402201325836f97262e6aadd70e116cdb7e048e0ae2fdd1da4b671e71ff71a58f78140220579dbfaafa899d9e9e87120f023ded1eb9aa9272c3d961731a67ecf32e1f333a01483045022100a282fce0fcde0522bcbcd35328582679b2e160cefa899c29f5523ad9f01277c802202acfa1afc8d8b01ae94b565901acfa179d57ca429a20071fe96418f9f78857e801483045022100829fcb4c530b0ece63f4354c750658be3cb825f047578a0505cb37c265cc0b8802200150d50c8dded79f9e47479238a4e5cbd5b803a353e5fde8ded524ec77be9b7801483045022100f3663c0d0cef0ac46b98c3d14392d9b9007a1c2f47a754fc44db6c8292bad25402201645b4181c5e1ee4aeb89dc54b10d12979632394e55381aea4d0f987122509b10147304402205d6ff8dcc4380d36a166c278b0b20ad8c8fcdd288a40f7e8d57c386be74db402022004c3e114b3ef5df45ce3873d468facd6337c382b5b759e9e219564c5bc351ad6014dd10157410446f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695ce94104704e19d4fc234a42d707d41053c87011f990b564949532d72cab009e136bd60d7d0602f925fce79da77c0dfef4a49c6f44bd0540faef548e37557d74b36da1244104b75a8cb10fd3f1785addbafdb41b409ecd6ffd50d5ad71d8a3cdc5503bcb35d3d13cdf23f6d0eb6ab88446276e2ba5b92d8786da7e5c0fb63aafb62f87443d284104033a82ccb1291bbc27cf541c6c487c213f25db85c620ecb9cbb76ca461ef13db5a80b90c3ae7d2a5e47623cdf520a2586cac7e41f779103a71a1fe177189781e41045e3b4030be5fd9c4c40e7076bd49f022118d90ae9182de61f3a1adb2ff511c97e8a6a82a9292b01878a18c08b7cd658ebdf80e6ed3f26783b25ba1a52fa9e52d4104c93ceb8f4482e131addc58d3efa0b4967bb7c574de15786d55379cc4a43a61571518abe0f05ebf188bcce9580aa70b3f5b1024ca579819c8810ff79967de3f234104a66f63d2941f0befcfba4b73495a7b99fc7ed28cb41e7934e1de82d852628766dc96ee1e196387a68e7fd8898862c2260f1f2557ac2147af07900695f15abd3f57aeffffffff0150270100000000001976a9149203e47a16f799ded03532e3e452606fdc52007e88ac00000000"

		finalTransactionHex, err := btcp2sh.GenerateSpend(testPrivateKeys, testDestination, testRedeemScript, testInputTx, testAmount)
		if err != nil {
			t.Fatalf("Error while generating spend transaction %s", err.Error())
		}
		if testFinalTransactionHex != finalTransactionHex {
			CompareError(t, "Generated spend transaction different from expected transaction.", testFinalTransactionHex, finalTransactionHex)
		}
	}
	{
		//7-of-7 spending multisig test
		testPrivateKeys := "5JruagvxNLXTnkksyLMfgFgf3CagJ3Ekxu5oGxpTm5mPfTAPez3,5JjHVMwJdjPEPQhq34WMUhzLcEd4SD7HgZktEh8WHstWcCLRceV"
		testDestination := "18tiB1yNTzJMCg6bQS1Eh29dvJngq8QTfx"
		testRedeemScript := "524104a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd41046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187410411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e8353ae"
		testInputTx := "02b082113e35d5386285094c2829e7e2963fa0b5369fb7f4b79c4c90877dcd3d"
		testAmount := 55600
		testFinalTransactionHex := "01000000013dcd7d87904c9cb7f4b79f36b5a03f96e2e729284c09856238d5353e1182b00200000000fd5e0100483045022100af4831eb0cee1b9642ff8691acb53c2fd8e28bbd6c0389af69c132b342405c8502200627e67cbb0bee502421be4d2b8e370d24eb17ff7c3d77d604a5c07ee5934a74014830450221009bfee48a5ae99a8fc0f78c631b0b2beb6d96337fc9d1e95c333a08bdcecb3647022040a30b3528b136821077d0bb45c324d7eedcd0ac61af7019ba1286e9277b7c54014cc9524104a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd41046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187410411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e8353aeffffffff0130d90000000000001976a914569076ba39fc4ff6a2291d9ea9196d8c08f9c7ab88ac00000000"

		finalTransactionHex, err := btcp2sh.GenerateSpend(testPrivateKeys, testDestination, testRedeemScript, testInputTx, testAmount)
		if err != nil {
			t.Fatalf("Error while generating spend transaction %s", err.Error())
		}
		if testFinalTransactionHex != finalTransactionHex {
			CompareError(t, "Generated spend transaction different from expected transaction.", testFinalTransactionHex, finalTransactionHex)
		}
	}
}

func TestSignMultisigTransaction(t *testing.T) {
	btc.SetFixedNonce = true //SetFixedNonce set to true to get repeatable signatures with a fixed nonce for testing.
	{
		testRawTransanction := []byte{1, 0, 0, 0, 1, 61, 205, 125, 135, 144, 76, 156, 183, 244, 183, 159, 54, 181, 160, 63, 150, 226, 231, 41, 40, 76, 9, 133, 98, 56, 213, 53, 62, 17, 130, 176, 2, 0, 0, 0, 0, 201, 82, 65, 4, 168, 130, 212, 20, 228, 120, 3, 156, 213, 181, 42, 146, 255, 177, 61, 213, 230, 189, 69, 21, 73, 116, 57, 223, 253, 105, 26, 15, 18, 175, 149, 117, 250, 52, 155, 86, 148, 237, 49, 85, 177, 54, 240, 158, 99, 151, 90, 23, 0, 201, 244, 212, 223, 132, 147, 35, 218, 192, 108, 243, 189, 100, 88, 205, 65, 4, 108, 227, 29, 185, 189, 213, 67, 231, 47, 227, 3, 154, 31, 28, 4, 125, 171, 135, 3, 124, 54, 166, 105, 255, 144, 226, 141, 161, 132, 143, 100, 13, 230, 140, 47, 233, 19, 211, 99, 165, 17, 84, 160, 198, 45, 122, 222, 161, 184, 34, 208, 80, 53, 7, 116, 24, 38, 123, 26, 19, 121, 121, 1, 135, 65, 4, 17, 255, 211, 108, 112, 119, 101, 56, 208, 121, 251, 174, 17, 125, 195, 142, 255, 175, 179, 51, 4, 175, 131, 206, 72, 148, 88, 151, 71, 174, 225, 239, 153, 47, 99, 40, 5, 103, 245, 47, 91, 168, 112, 103, 139, 74, 180, 255, 108, 142, 166, 0, 189, 33, 120, 112, 168, 180, 241, 240, 159, 58, 142, 131, 83, 174, 255, 255, 255, 255, 1, 48, 217, 0, 0, 0, 0, 0, 0, 25, 118, 169, 20, 86, 144, 118, 186, 57, 252, 79, 246, 162, 41, 29, 158, 169, 25, 109, 140, 8, 249, 199, 171, 136, 172, 0, 0, 0, 0, 1, 0, 0, 0}
		testOrderedPrivateKeys := [][]byte{
			[]byte{137, 165, 141, 245, 104, 126, 111, 88, 250, 23, 75, 123, 32, 161, 84, 132, 246, 150, 102, 14, 91, 248, 78, 160, 54, 237, 253, 196, 124, 205, 97, 198},
			[]byte{120, 86, 226, 122, 244, 47, 75, 154, 241, 209, 174, 51, 83, 165, 92, 104, 125, 6, 106, 57, 81, 117, 39, 120, 142, 130, 212, 196, 42, 85, 199, 89},
		}
		testScriptPubKey := []byte{118, 169, 20, 86, 144, 118, 186, 57, 252, 79, 246, 162, 41, 29, 158, 169, 25, 109, 140, 8, 249, 199, 171, 136, 172}
		testRedeemScript := []byte{82, 65, 4, 168, 130, 212, 20, 228, 120, 3, 156, 213, 181, 42, 146, 255, 177, 61, 213, 230, 189, 69, 21, 73, 116, 57, 223, 253, 105, 26, 15, 18, 175, 149, 117, 250, 52, 155, 86, 148, 237, 49, 85, 177, 54, 240, 158, 99, 151, 90, 23, 0, 201, 244, 212, 223, 132, 147, 35, 218, 192, 108, 243, 189, 100, 88, 205, 65, 4, 108, 227, 29, 185, 189, 213, 67, 231, 47, 227, 3, 154, 31, 28, 4, 125, 171, 135, 3, 124, 54, 166, 105, 255, 144, 226, 141, 161, 132, 143, 100, 13, 230, 140, 47, 233, 19, 211, 99, 165, 17, 84, 160, 198, 45, 122, 222, 161, 184, 34, 208, 80, 53, 7, 116, 24, 38, 123, 26, 19, 121, 121, 1, 135, 65, 4, 17, 255, 211, 108, 112, 119, 101, 56, 208, 121, 251, 174, 17, 125, 195, 142, 255, 175, 179, 51, 4, 175, 131, 206, 72, 148, 88, 151, 71, 174, 225, 239, 153, 47, 99, 40, 5, 103, 245, 47, 91, 168, 112, 103, 139, 74, 180, 255, 108, 142, 166, 0, 189, 33, 120, 112, 168, 180, 241, 240, 159, 58, 142, 131, 83, 17}
		testInputTx := "02b082113e35d5386285094c2829e7e2963fa0b5369fb7f4b79c4c90877dcd3d"
		testAmount := 55600
		testSignedTx := []byte{1, 0, 0, 0, 1, 61, 205, 125, 135, 144, 76, 156, 183, 244, 183, 159, 54, 181, 160, 63, 150, 226, 231, 41, 40, 76, 9, 133, 98, 56, 213, 53, 62, 17, 130, 176, 2, 0, 0, 0, 0, 253, 94, 1, 0, 72, 48, 69, 2, 33, 0, 175, 72, 49, 235, 12, 238, 27, 150, 66, 255, 134, 145, 172, 181, 60, 47, 216, 226, 139, 189, 108, 3, 137, 175, 105, 193, 50, 179, 66, 64, 92, 133, 2, 32, 6, 39, 230, 124, 187, 11, 238, 80, 36, 33, 190, 77, 43, 142, 55, 13, 36, 235, 23, 255, 124, 61, 119, 214, 4, 165, 192, 126, 229, 147, 74, 116, 1, 72, 48, 69, 2, 33, 0, 155, 254, 228, 138, 90, 233, 154, 143, 192, 247, 140, 99, 27, 11, 43, 235, 109, 150, 51, 127, 201, 209, 233, 92, 51, 58, 8, 189, 206, 203, 54, 71, 2, 32, 64, 163, 11, 53, 40, 177, 54, 130, 16, 119, 208, 187, 69, 195, 36, 215, 238, 220, 208, 172, 97, 175, 112, 25, 186, 18, 134, 233, 39, 123, 124, 84, 1, 76, 201, 82, 65, 4, 168, 130, 212, 20, 228, 120, 3, 156, 213, 181, 42, 146, 255, 177, 61, 213, 230, 189, 69, 21, 73, 116, 57, 223, 253, 105, 26, 15, 18, 175, 149, 117, 250, 52, 155, 86, 148, 237, 49, 85, 177, 54, 240, 158, 99, 151, 90, 23, 0, 201, 244, 212, 223, 132, 147, 35, 218, 192, 108, 243, 189, 100, 88, 205, 65, 4, 108, 227, 29, 185, 189, 213, 67, 231, 47, 227, 3, 154, 31, 28, 4, 125, 171, 135, 3, 124, 54, 166, 105, 255, 144, 226, 141, 161, 132, 143, 100, 13, 230, 140, 47, 233, 19, 211, 99, 165, 17, 84, 160, 198, 45, 122, 222, 161, 184, 34, 208, 80, 53, 7, 116, 24, 38, 123, 26, 19, 121, 121, 1, 135, 65, 4, 17, 255, 211, 108, 112, 119, 101, 56, 208, 121, 251, 174, 17, 125, 195, 142, 255, 175, 179, 51, 4, 175, 131, 206, 72, 148, 88, 151, 71, 174, 225, 239, 153, 47, 99, 40, 5, 103, 245, 47, 91, 168, 112, 103, 139, 74, 180, 255, 108, 142, 166, 0, 189, 33, 120, 112, 168, 180, 241, 240, 159, 58, 142, 131, 83, 17, 255, 255, 255, 255, 1, 48, 217, 0, 0, 0, 0, 0, 0, 25, 118, 169, 20, 86, 144, 118, 186, 57, 252, 79, 246, 162, 41, 29, 158, 169, 25, 109, 140, 8, 249, 199, 171, 136, 172, 0, 0, 0, 0}

		signedTx, err := btcp2sh.SignMultiSigTransaction(testRawTransanction, testOrderedPrivateKeys, testScriptPubKey, testRedeemScript, testInputTx, testAmount)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(testSignedTx, signedTx) {
			CompareError(t, "Generated signature different from expected signature.", testSignedTx, signedTx)
		}
	}
}