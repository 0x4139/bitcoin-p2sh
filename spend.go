package btcp2sh

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"strings"
	"github.com/0x4139/bitcoin-p2sh/btc"
	"github.com/0x4139/bitcoin-p2sh/base58"
	"fmt"
)

func GenerateSpend(rawPrivateKeys string, destination string, rawRedeemScript string, inputTx string, amount int) (string, error) {
	redeemScript, err := hex.DecodeString(rawRedeemScript)
	if err != nil {
		return "", err
	}
	rawPrivateKeys = strings.Replace(rawPrivateKeys, "'", "\"", -1) //Replace single quotes with double since csv package only recognizes double quotes
	privateKeyStrings, err := csv.NewReader(strings.NewReader(rawPrivateKeys)).Read()
	if err != nil {
		return "", err
	}
	privateKeys := make([][]byte, len(privateKeyStrings))
	for i, privateKeyString := range privateKeyStrings {
		privateKeyString = strings.TrimSpace(privateKeyString) //Trim whitespace
		if privateKeyString == "" {
			return "", fmt.Errorf("provided private key cannot be empty")
		}
		privateKeys[i] = base58.Decode(privateKeyString) //Get private keys as slice of raw bytes
	}
	publicKeyHash := base58.Decode(destination)
	scriptPubKey, err := btc.NewP2PKHScriptPubKey(publicKeyHash)
	if err != nil {
		return "", err
	}
	rawTransaction, err := btc.NewRawTransaction(inputTx, amount, redeemScript, scriptPubKey)
	if err != nil {
		return "", err
	}
	hashCodeType, err := hex.DecodeString("01000000")
	if err != nil {
		return "", err
	}
	var rawTransactionBuffer bytes.Buffer
	rawTransactionBuffer.Write(rawTransaction)
	rawTransactionBuffer.Write(hashCodeType)
	rawTransactionWithHashCodeType := rawTransactionBuffer.Bytes()
	finalTransaction, err := SignMultiSigTransaction(rawTransactionWithHashCodeType, privateKeys, scriptPubKey, redeemScript, inputTx, amount)
	if err != nil {
		return "", err
	}
	finalTransactionHex := hex.EncodeToString(finalTransaction)

	return finalTransactionHex, nil
}

func SignMultiSigTransaction(rawTransaction []byte, orderedPrivateKeys [][]byte, scriptPubKey []byte, redeemScript []byte, inputTx string, amount int) ([]byte, error) {
	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		return nil, err
	}
	signatures := make([][]byte, len(orderedPrivateKeys))
	for i, privateKey := range orderedPrivateKeys {
		signatures[i], err = btc.NewSignature(rawTransaction, privateKey)
		if err != nil {
			return nil, err
		}
	}
	var redeemScriptLengthBytes []byte
	var requiredOP_PUSHDATA int
	if len(redeemScript) < 255 {
		requiredOP_PUSHDATA = btc.OP_PUSHDATA1
		redeemScriptLengthBytes = []byte{byte(len(redeemScript))}
	} else {
		requiredOP_PUSHDATA = btc.OP_PUSHDATA2
		redeemScriptLengthBytes = make([]byte, 2)
		binary.LittleEndian.PutUint16(redeemScriptLengthBytes, uint16(len(redeemScript)))
	}
	var buffer bytes.Buffer
	buffer.WriteByte(byte(btc.OP_0))
	for _, signature := range signatures {
		buffer.WriteByte(byte(len(signature) + 1))
		buffer.Write(signature)
		buffer.WriteByte(hashCodeType[0])
	}
	buffer.WriteByte(byte(requiredOP_PUSHDATA))
	buffer.Write(redeemScriptLengthBytes)
	buffer.Write(redeemScript)
	scriptSig := buffer.Bytes()
	signedRawTransaction, err := btc.NewRawTransaction(inputTx, amount, scriptSig, scriptPubKey)
	if err != nil {
		return nil, err
	}
	return signedRawTransaction, nil
}
