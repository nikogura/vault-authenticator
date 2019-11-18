package authenticator

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"os"
)

// TLSLogin logs a host into Vault via it's certificates.  Intended for hosts, not users
func TLSLogin(authenticator *Authenticator) (client *api.Client, err error) {
	if authenticator.Role == "" {
		err = errors.New("No role given.  Cannot auth.")
		return client, err
	}

	if authenticator.TlsClientCrtPath == "" {
		err = errors.New("Cannot perform TLS Auth without a client certificate")
		return client, err
	}

	if authenticator.TlsClientKeyPath == "" {
		err = errors.New("Cannot perform TLS Auth without a client key")
		return client, err
	}

	verboseOutput(authenticator.Verbose, "Attempting TLS Login with cert: %s and key %s...", authenticator.TlsClientCrtPath, authenticator.TlsClientKeyPath)

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

	if _, err := os.Stat(authenticator.TlsClientCrtPath); !os.IsNotExist(err) {
		if _, err := os.Stat(authenticator.TlsClientKeyPath); !os.IsNotExist(err) {
			// We'll try to do cert auth using the host's vault key
			tlsConfig := api.TLSConfig{
				ClientCert: authenticator.TlsClientCrtPath,
				ClientKey:  authenticator.TlsClientKeyPath,
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
			err = errors.New(fmt.Sprintf("private key %q does not exist", authenticator.TlsClientKeyPath))
			return client, err
		}
	} else {
		err = errors.New(fmt.Sprintf("certificate %q does not exist", authenticator.TlsClientCrtPath))
		return client, err
	}
	return client, err
}
