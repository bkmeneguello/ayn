package main

import (
	"crypto/rsa"
	"net/http"

	"flag"
	"fmt"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"

	"github.com/bkmeneguello/ayn/config"
	"github.com/bkmeneguello/ayn/key"
	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
)

const DefaultConfigFile = "config.toml"
const DefaultStorageFile = "storage.db"
const Posts = "Posts"

var configFile string
var homePath string
var storagePath string

func init() {
	flag.StringVar(&configFile, "config", "", "config file path")
	flag.StringVar(&homePath, "home", "", "application base path")
	flag.StringVar(&storagePath, "storage", "", "application storage path")
}

func main() {
	flag.Parse()

	if homePath == "" {
		currentUser, err := user.Current()
		if err != nil {
			panic(err)
		}
		homePath = path.Join(currentUser.HomeDir, ".ayn")
	}

	if configFile == "" {
		configFile = path.Join(homePath, DefaultConfigFile)
	}

	conf, err := config.Parse(configFile)
	if err != nil {
		panic(err)
	}

	if storagePath == "" {
		storagePath = path.Join(homePath, DefaultStorageFile)
	}

	db, err := bolt.Open(storagePath, 0600, nil)
	defer db.Close()

	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(Posts))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})

	keys := loadKeys(conf)

	router := mux.NewRouter().StrictSlash(true)
	router.Methods("POST").Path("/sign/{key}").Handler(&PostSignHandler{keys, db})
	router.Methods("GET").Path("/posts").Handler(&PostsHandler{db})
	addr := strings.Join([]string{conf.SignEndpoint.Host, strconv.Itoa(conf.SignEndpoint.Port)}, ":")

	if conf.SignEndpoint.TLSEnabled {
		http.ListenAndServeTLS(addr, conf.SignEndpoint.TLSCertFile, conf.SignEndpoint.TLSKeyFile, router)
	} else {
		http.ListenAndServe(addr, router)
	}
}

func loadKeys(conf *config.Config) (keys map[string]*rsa.PrivateKey) {
	keys = make(map[string]*rsa.PrivateKey)
	for keyName, keyDef := range conf.Keys {
		file, err := os.Open(keyDef.Path)
		if err != nil {
			panic(err)
		}
		key.ReadPrivateKey(file, "", func(alias string) string {
			return keyDef.Password
		}, func(pk *rsa.PrivateKey) {
			keys[keyName] = pk
		})
	}
	return keys
}
