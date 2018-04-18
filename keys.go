package btcp2sh

import (
	"encoding/hex"
	"github.com/0x4139/bitcoin-p2sh/base58"
	"github.com/0x4139/bitcoin-p2sh/btc"
)

func GenerateKeys(keyCount int) ([]string, []string, []string, error) {
	publicKeyHexs := make([]string, keyCount)
	publicAddresses := make([]string, keyCount)
	privateKeyWIFs := make([]string, keyCount)

	for i := 0; i <= keyCount-1; i++ {
		privateKey := btc.NewPrivateKey()
		publicKey, err := btc.NewPublicKey(privateKey)
		if err != nil {
			return nil, nil, nil, err
		}
		publicKeyHexs[i] = hex.EncodeToString(publicKey)
		publicKeyHash, err := btc.Hash160(publicKey)
		if err != nil {
			return nil, nil, nil, err
		}
		publicAddresses[i] = base58.Encode("00", publicKeyHash)
		privateKeyWIFs[i] = base58.Encode("80", privateKey)
	}

	return privateKeyWIFs, publicKeyHexs, publicAddresses, nil
}
