package main

import (
	"crypto/rsa"
	"net/http"

	"encoding/json"
	"fmt"
	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
	"io/ioutil"
)

type PostSignHandler struct {
	Keys map[string]*rsa.PrivateKey
	DB   *bolt.DB
}

func (h *PostSignHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	keyName, ok := vars["key"]
	if !ok {
		panic(fmt.Errorf("missing key name"))
	}

	defer req.Body.Close()
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	post := new(Post)
	err = json.Unmarshal(body, post)
	if err != nil {
		panic(err)
	}

	privateKey, ok := h.Keys[keyName]
	if !ok {
		panic(fmt.Errorf("missing keyName %s", keyName))
	}
	response, err := post.Marshall(privateKey)
	if err != nil {
		panic(err)
	}
	h.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(Posts))
		return b.Put(post.Signature.Hash, response)
	})

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

type PostsHandler struct {
	DB *bolt.DB
}

func (h *PostsHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	w.Write([]byte("["))
	sep := false
	h.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(Posts))
		b.ForEach(func(k, v []byte) error {
			if sep {
				w.Write([]byte(","))
			}
			w.Write(v)
			sep = true
			return nil
		})
		return nil
	})
	w.Write([]byte("]"))

}
