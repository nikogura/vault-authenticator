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

	verboseOutput(authenticator.Verbose, "Attempting TLS Login with cert: %s and key: %s ...", authenticator.TlsClientCrtPath, authenticator.TlsClientKeyPath)

	apiConfig, err := ApiConfig(authenticator.Address, authenticator.CACertificate)
	if err != nil {
		err = errors.Wrap(err, "failed creating vault api config")
	}

	if _, err := os.Stat(authenticator.TlsClientCrtPath); !os.IsNotExist(err) {
		if _, err := os.Stat(authenticator.TlsClientKeyPath); !os.IsNotExist(err) {
			tlsConfig := api.TLSConfig{
				ClientCert: authenticator.TlsClientCrtPath,
				ClientKey:  authenticator.TlsClientKeyPath,
				Insecure:   false,
			}

			apiConfig.ConfigureTLS(&tlsConfig)

			client, err = api.NewClient(apiConfig)
			if err != nil {
				err = errors.Wrapf(err, "failed creating vault api client")
				return client, err
			}

			loginData := make(map[string]interface{})
			loginData["name"] = authenticator.Role

			path := "auth/cert/login"
			verboseOutput(authenticator.Verbose, "  login path is %s/%s", apiConfig.Address, path)
			verboseOutput(authenticator.Verbose, "  login role is %s", authenticator.Role)
			verboseOutput(authenticator.Verbose, "  login data: %s\n", loginData)

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
