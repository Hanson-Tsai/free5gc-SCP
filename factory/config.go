/*
 * SCP Configuration Factory
 */

package factory

import (
	"github.com/free5gc/logger_util"
)

const (
	SCP_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info               `yaml:"info"`
	Configuration *Configuration      `yaml:"configuration"`
	Logger        *logger_util.Logger `yaml:"logger"`
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

const (
	SCP_DEFAULT_IPV4     = "127.0.0.113"
	SCP_DEFAULT_PORT     = "8000"
	SCP_DEFAULT_PORT_INT = 8000
)

type Configuration struct {
	ScpName         string    `yaml:"scpName,omitempty"`
	Sbi             *Sbi      `yaml:"sbi,omitempty"`
	NrfUri          string    `yaml:"nrfUri,omitempty"`
}

type Sbi struct {
	Scheme       string `yaml:"scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	// IPv6Addr  string `yaml:"ipv6Addr,omitempty"`
	BindingIPv4 string `yaml:"bindingIPv4,omitempty"` // IP used to run the server in the node.
	Port        int    `yaml:"port,omitempty"`
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
