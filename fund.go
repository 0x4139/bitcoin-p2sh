package btcp2sh

import (
	"bytes"
	"encoding/hex"
	"github.com/0x4139/bitcoin-p2sh/base58"
	"github.com/0x4139/bitcoin-p2sh/btc"
)

func GenerateFund(rawPrivateKey string, inputTx string, amount int, p2shDestination string) (string, error) {
	privateKey := base58.Decode(rawPrivateKey)
	publicKey, err := btc.NewPublicKey(privateKey)
	if err != nil {
		return "", err
	}
	publicKeyHash, err := btc.Hash160(publicKey)
	if err != nil {
		return "", err
	}
	tempScriptSig, err := btc.NewP2PKHScriptPubKey(publicKeyHash)
	if err != nil {
		return "", err
	}
	redeemScriptHash := base58.Decode(p2shDestination)
	scriptPubKey, err := btc.NewP2SHScriptPubKey(redeemScriptHash)
	if err != nil {
		return "", err
	}
	rawTransaction, err := btc.NewRawTransaction(inputTx, amount, tempScriptSig, scriptPubKey)
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
	finalTransaction, err := SignP2PKHTransaction(rawTransactionWithHashCodeType, privateKey, scriptPubKey, inputTx, amount)
	if err != nil {
		return "", err
	}
	finalTransactionHex := hex.EncodeToString(finalTransaction)

	return finalTransactionHex, nil
}

func SignP2PKHTransaction(rawTransaction []byte, privateKey []byte, scriptPubKey []byte, inputTx string, amount int) ([]byte, error) {
	publicKey, err := btc.NewPublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	signature, err := btc.NewSignature(rawTransaction, privateKey)
	if err != nil {
		return nil, err
	}
	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		return nil, err
	}
	signatureLength := byte(len(signature) + 1)
	var buffer bytes.Buffer
	buffer.WriteByte(signatureLength)
	buffer.Write(signature)
	buffer.WriteByte(hashCodeType[0])
	buffer.WriteByte(byte(len(publicKey)))
	buffer.Write(publicKey)
	scriptSig := buffer.Bytes()
	signedRawTransaction, err := btc.NewRawTransaction(inputTx, amount, scriptSig, scriptPubKey)
	if err != nil {
		return nil, err
	}
	return signedRawTransaction, nil
}
