package config

import (
	"github.com/naoina/toml"
	"io/ioutil"
	"os"
)

const DefaultPort = 11249

type Key struct {
	Path     string
	Password string
}

type Endpoint struct {
	Host        string
	Port        int
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
}

type Config struct {
	PullEndpoint Endpoint
	PushEndpoint Endpoint
	SignEndpoint Endpoint
	Keys         map[string]Key
}

func Parse(name string) (config *Config, err error) {
	config = &Config{
		PullEndpoint:Endpoint{
			Port:DefaultPort,
		},
		PushEndpoint:Endpoint{
			Port:DefaultPort,
		},
		SignEndpoint:Endpoint{
			Port:DefaultPort,
		},
	}
	if _, err = os.Stat(name); err == nil {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		buf, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}
		err = toml.Unmarshal(buf, config)
		if err != nil {
			return nil, err
		}
	}
	return config, err
}
