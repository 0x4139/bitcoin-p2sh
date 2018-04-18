Bitcoin p2sh (multisig)
======
[![Documentation Status](https://readthedocs.org/projects/ansicolortags/badge/?version=latest)](http://ansicolortags.readthedocs.io/?badge=latest) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)


### Important: Be sure that you use golang < 1.9.4 due to the fact of this [Issue](https://github.com/golang/go/issues/23739)

### Install go bindings for bitcoin secp256k1 first

```
cd $GOPATH/src/github.com/0x4139/secp256k1
git submodule update
cd c-secp256k1
make distclean && ./autogen.sh && ./configure && make
cd ..
go clean && go install
```

### Run the tests

```
go test tests
```

### Features
For a more detailed usage please see the folder `tests`
```
GenerateAddress(m int, n int, rawPublicKeys string) (string, string, error)
GenerateFund(rawPrivateKey string, inputTx string, amount int, p2shDestination string) (string, error)
SignP2PKHTransaction(rawTransaction []byte, privateKey []byte, scriptPubKey []byte, inputTx string, amount int) ([]byte, error) 
GenerateKeys(keyCount int) ([]string, []string, []string, error)
GenerateSpend(rawPrivateKeys string, destination string, rawRedeemScript string, inputTx string, amount int) (string, error)
SignMultiSigTransaction(rawTransaction []byte, orderedPrivateKeys [][]byte, scriptPubKey []byte, redeemScript []byte, inputTx string, amount int) ([]byte, error) 
```

#### Important Information
As per protocol rfc, private keys in ort to spend a multisig wallet have to be provided in the same order (skipping is ok but in the same order) as provided when the P2SH address was created


### License

````
  DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2018 <s0x4139@gmail.com>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
````