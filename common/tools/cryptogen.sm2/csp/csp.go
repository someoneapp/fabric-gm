/*
Copyright Beijing Sansec Technology Development Co., Ltd. 2017 All Rights Reserved.
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package csp

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/warm3snow/gmsm/sm2"
)

// GeneratePrivateKey creates a private key and stores it in keystorePath
func GeneratePrivateKey(keystorePath string) (bccsp.Key,
	crypto.Signer, error) {

	var err error
	var priv bccsp.Key
	var s crypto.Signer

	opts := &factory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,

			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: keystorePath,
			},
		},
	}
	csp, err := factory.GetBCCSPFromOpts(opts)
	if err == nil {
		// generate a key
		priv, err = csp.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
		if err == nil {
			// create a crypto.Signer
			s, err = signer.New(csp, priv)
		}
	}
	return priv, s, err
}

//return a *sm2.PublicKey
func GetSM2PublicKey(priv bccsp.Key) (*sm2.PublicKey, error) {
	pubKey, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}

	//sm2PubKey, err := sm2.ParseSm2PublicKey(pubKeyBytes)
	pub, err := utils.DERToPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	switch pub.(type) {
	case *sm2.PublicKey:
		fmt.Println("GetPublicKey returns a *sm2.PublicKey")
		return pub.(*sm2.PublicKey), nil
	case *ecdsa.PublicKey:
		fmt.Println("GetPublicKey returns a *ecdsa.PublicKey")
		return nil, errors.New("FAIL, Expected sm2.PublicKey, got ecdsa.PublicKey")
		//return pub.(*ecdsa.PublicKey), nil
	}

	return nil, errors.New("Fail, Not a SM2 PublicKey")
}
