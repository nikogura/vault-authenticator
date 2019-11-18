package vaultlibs

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"os"
)

const TLS_CLIENT_CERT_PATH = "/etc/vault/host.crt"
const TLS_CLIENT_KEY_PATH = "/etc/vault/host.key"

// DetectTls See if we have a certificate and private key in the normal location for a SL host.
func DetectTls(c chan bool, verbose bool) {
	// check to see if the key and cert exist
	if _, err := os.Stat(TLS_CLIENT_KEY_PATH); os.IsNotExist(err) {
		c <- false
	} else {
		if _, err := os.Stat(TLS_CLIENT_CERT_PATH); os.IsNotExist(err) {
			c <- false
		} else {
			c <- true
		}
	}
}

// TLSLogin logs a host into Vault via it's certificates.  Intended for hosts, not users
func TLSLogin(authenticator *Authenticator) (client *api.Client, err error) {
	verboseOutput(authenticator.Verbose, "Attempting TLS Login...")

	if authenticator.Role == "" {
		err = errors.New("No role given.  Cannot auth.")
		return client, err
	}

	apiConfig := api.DefaultConfig()
	err = apiConfig.ReadEnvironment()
	if err != nil {
		err = errors.Wrapf(err, "failed to inject environment into client authenticator")
		return client, err
	}

	if apiConfig.Address == "https://127.0.0.1:8200" {
		if authenticator.Address != "" {
			apiConfig.Address = authenticator.Address
		}
	}

	if _, err := os.Stat(TLS_CLIENT_CERT_PATH); !os.IsNotExist(err) {
		if _, err := os.Stat(TLS_CLIENT_KEY_PATH); !os.IsNotExist(err) {
			// We'll try to do cert auth using the host's vault key
			tlsConfig := api.TLSConfig{
				ClientCert: TLS_CLIENT_CERT_PATH,
				ClientKey:  TLS_CLIENT_KEY_PATH,
				Insecure:   false,
			}

			apiConfig.ConfigureTLS(&tlsConfig)

			client, err = api.NewClient(apiConfig)

			loginData := make(map[string]interface{})
			loginData["name"] = authenticator.Role

			path := "auth/cert/login"
			verboseOutput(authenticator.Verbose, "  login path is %s/%s", apiConfig.Address, path)
			verboseOutput(authenticator.Verbose, "  login role is %s", authenticator.Role)

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

			verboseOutput(authenticator.Verbose, "Success!\n")
			return client, err

		} else {
			err = errors.New(fmt.Sprintf("private key %s does not exist", TLS_CLIENT_KEY_PATH))
			return client, err
		}
	} else {
		err = errors.New(fmt.Sprintf("certificate %s does not exist", TLS_CLIENT_CERT_PATH))
		return client, err
	}
	return client, err
}
