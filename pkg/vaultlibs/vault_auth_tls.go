package vaultlibs

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"os"
)

const HOST_CERT_PATH = "/etc/vault/host.crt"
const HOST_KEY_PATH = "/etc/vault/host.key"

// DetectTls See if we have a certificate and private key in the normal location for a SL host.
func DetectTls(c chan bool, verbose bool) {
	// check to see if the key and cert exist
	if _, err := os.Stat(HOST_KEY_PATH); os.IsNotExist(err) {
		c <- false
	} else {
		if _, err := os.Stat(HOST_CERT_PATH); os.IsNotExist(err) {
			c <- false
		} else {
			c <- true
		}
	}
}

// TLSLogin logs a host into Vault via it's certificates.  Intended for hosts, not users
func TLSLogin(rolename string, verbose bool) (client *api.Client, err error) {
	VerboseOutput(verbose, "Attempting TLS Login...")

	if rolename == "" {
		VerboseOutput(verbose, "  No rolename given.  Attempting Legacy TLS Auth\n")
		return LegacyCertAuth()
	}

	config := api.DefaultConfig()
	err = config.ReadEnvironment()
	if err != nil {
		err = errors.Wrapf(err, "failed to inject environment into client config")
		return client, err
	}

	if config.Address == "https://127.0.0.1:8200" {
		config.Address = DEFAULT_VAULT_ADDR
	}

	if _, err := os.Stat(CLIENT_CERT_PATH); !os.IsNotExist(err) {
		if _, err := os.Stat(CLIENT_KEY_PATH); !os.IsNotExist(err) {
			// We'll try to do cert auth using the host's vault key
			tlsConfig := api.TLSConfig{
				ClientCert: HOST_CERT_PATH,
				ClientKey:  HOST_KEY_PATH,
				Insecure:   false,
			}

			config.ConfigureTLS(&tlsConfig)

			client, err = api.NewClient(config)

			loginData := make(map[string]interface{})
			loginData["name"] = rolename

			path := "auth/cert/login"
			VerboseOutput(verbose, "  login path is %s/%s", config.Address, path)
			VerboseOutput(verbose, "  login role is %s", rolename)

			loginSecret, err := client.Logical().Write(path, loginData)
			if err != nil {
				err = errors.Wrapf(err, "failed to perform cert login to vault")
				return client, err
			}

			if loginSecret == nil {
				err = errors.New(fmt.Sprintf("no auth data returned on login"))
				return client, err
			}

			token := loginSecret.Auth.ClientToken

			if token == "" {
				err = errors.New("empty token")
				return client, err
			}

			client.SetToken(token)

			VerboseOutput(verbose, "Success!\n")
			return client, err

		} else {
			err = errors.New(fmt.Sprintf("private key %s does not exist", CLIENT_KEY_PATH))
			return client, err
		}
	} else {
		err = errors.New(fmt.Sprintf("certificate %s does not exist", CLIENT_CERT_PATH))
		return client, err
	}
	return client, err
}

// LegacyCertAuth logs a host into Vault via it's certificate in the manner expected by SecretsV1
func LegacyCertAuth() (client *api.Client, err error) {
	config := api.DefaultConfig()
	err = config.ReadEnvironment()
	if err != nil {
		err = errors.Wrapf(err, "failed to inject environment into client config")
		return client, err
	}

	if config.Address == "https://127.0.0.1:8200" {
		config.Address = DEFAULT_VAULT_ADDR
	}

	if _, err := os.Stat(CLIENT_CERT_PATH); !os.IsNotExist(err) {
		if _, err := os.Stat(CLIENT_KEY_PATH); !os.IsNotExist(err) {
			// We'll try to do cert auth using the host's vault key
			tlsConfig := api.TLSConfig{
				ClientCert: HOST_CERT_PATH,
				ClientKey:  HOST_KEY_PATH,
				Insecure:   false,
			}
			config.ConfigureTLS(&tlsConfig)

			client, err = api.NewClient(config)

			loginData := make(map[string]interface{})
			loginRole := os.Getenv("VAULT_LOGIN_ROLE")

			// if env var for vault login role is present, use it
			if loginRole != "" {
				loginData["name"] = loginRole
			} else if os.Getenv("CI") != "" { // else look for the env var 'CI', set by gitlab
				loginData["name"] = "ci"
			}

			loginSecret, err := client.Logical().Write("auth/cert/login", loginData)
			if err != nil {
				err = errors.Wrapf(err, "failed to perform cert login to vault")
				return client, err
			}

			token := loginSecret.Auth.ClientToken
			client.SetToken(token)

			return client, err
		}
	}
	return client, err
}
