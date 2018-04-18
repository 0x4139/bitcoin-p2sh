package btcp2sh

import (
	"encoding/csv"
	"encoding/hex"
	"strings"
	"github.com/0x4139/bitcoin-p2sh/base58"
	"github.com/0x4139/bitcoin-p2sh/btc"
)

func GenerateAddress(m int, n int, rawPublicKeys string) (string, string, error) {
	rawPublicKeys = strings.Replace(rawPublicKeys, "'", "\"", -1)
	publicKeyStrings, err := csv.NewReader(strings.NewReader(rawPublicKeys)).Read()
	if err != nil {
		return "", "", err
	}
	publicKeys := make([][]byte, len(publicKeyStrings))
	for i, publicKeyString := range publicKeyStrings {
		publicKeyString = strings.TrimSpace(publicKeyString)
		publicKeys[i], err = hex.DecodeString(publicKeyString)
		if err != nil {
			return "", "", err
		}
	}
	redeemScript, err := btc.NewMOfNRedeemScript(m, n, publicKeys)
	if err != nil {
		return "", "", err
	}
	redeemScriptHash, err := btc.Hash160(redeemScript)
	if err != nil {
		return "", "", err
	}
	P2SHAddress := base58.Encode("05", redeemScriptHash)
	redeemScriptHex := hex.EncodeToString(redeemScript)
	return P2SHAddress, redeemScriptHex, nil
}
