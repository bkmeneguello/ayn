package main

import (
	"crypto/rand"
	"crypto/rsa"

	"bytes"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"

	"github.com/gibson042/canonicaljson-go"
)

type Key struct {
	Certificate []byte `json:"crt"`
}

type Signature struct {
	Hash []byte `json:"hash,omitempty"`
}

type Post struct {
	Content   interface{} `json:"content"`
	Key       *Key        `json:"key"`
	Signature *Signature  `json:"sig,omitempty"`
}

func init() {
	crypto.RegisterHash(crypto.SHA512, sha512.New)
}

func (post *Post) Marshall(key *rsa.PrivateKey) ([]byte, error) {
	pkix, err := x509.MarshalPKIXPublicKey(key.Public())
	post.Key = &Key{pkix}

	marshall, err := canonicaljson.Marshal(post)
	hash := crypto.SHA512
	hasher := hash.New()
	hasher.Write(marshall)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, hash, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}
	post.Signature = &Signature{signature}

	var buffer bytes.Buffer
	canonicaljson.NewEncoder(&buffer).Encode(&post)

	return buffer.Bytes(), nil
}

func (post *Post) Unmarshall(input []byte) error {
	err := json.Unmarshal(input, post)
	if err != nil {
		return err
	}

	key, err := x509.ParsePKIXPublicKey(post.Key.Certificate)
	if err != nil {
		return err
	}
	publicKey := key.(*rsa.PublicKey)

	signature := post.Signature.Hash
	post.Signature = nil

	marshall, err := canonicaljson.Marshal(post)
	hash := crypto.SHA512
	hasher := hash.New()
	hasher.Write(marshall)
	return rsa.VerifyPKCS1v15(publicKey, hash, hasher.Sum(nil), signature)
}
