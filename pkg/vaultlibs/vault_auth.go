package vaultlibs

import (
	tls2 "crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"net/http"
	"os"
)

const VAULT_TOKEN_ENV_VAR = "VAULT_TOKEN"
const VAULT_AUTH_FAIL = "vault login fail.  It didn't blow up, but also didn't return a token, either."

// VaultConfig A struct for setting fundamental information about how your org connects to Vault without needing to set ENV vars everywhere.  ENV Vars will still trump this value, but in their absence, this is a sane default for your org.
type VaultConfig struct {
	Address       string
	CACertificate string
	Prompt        bool
	Verbose       bool
	AuthMethods   []*AuthMethod
	Identifier    string
	Role          string
}

type AuthMethod struct {
	Name          string
	Authenticator func(config *VaultConfig) (client *api.Client, err error)
}

// VaultAuth Authenticates to Vault by a number of methods.  AWS IAM is preferred, but if that fails, it tries K8s, TLS, and finally LDAP
func VaultAuth(config *VaultConfig) (client *api.Client, err error) {
	// read the environment and use that over anything
	apiConfig := api.DefaultConfig()

	err = apiConfig.ReadEnvironment()
	if err != nil {
		err = errors.Wrapf(err, "failed to inject environment into client config")
		return client, err
	}

	if apiConfig.Address == "https://127.0.0.1:8200" {
		if config.Address != "" {
			apiConfig.Address = config.Address
		}
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		err = errors.Wrapf(err, "failed to get system cert pool")
		return client, err
	}

	if config.CACertificate != "" {
		ok := rootCAs.AppendCertsFromPEM([]byte(config.CACertificate))
		if !ok {
			err = errors.New("Failed to add scribd root cert to system CA bundle")
			return client, err
		}
	}

	clientConfig := &tls2.Config{
		RootCAs: rootCAs,
	}

	apiConfig.HttpClient.Transport = &http.Transport{TLSClientConfig: clientConfig}

	if config.Verbose {
		fmt.Printf("Vault Address: %s\n", apiConfig.Address)
		if config.CACertificate != "" {
			fmt.Printf("Private CA Cert in use.\n")
		}
	}

	client, err = api.NewClient(apiConfig)
	if err != nil {
		err = errors.Wrapf(err, "failed to create vault api client")
		return client, err
	}

	// Straight up take the token from the environment if provided
	if os.Getenv(VAULT_TOKEN_ENV_VAR) != "" {
		client.SetToken(os.Getenv(VAULT_TOKEN_ENV_VAR))
		return client, err
	}

	// Attempt to use a token on the filesystem if it exists
	ok, err := UseFSToken(client, config.Verbose)
	if err != nil {
		err = errors.Wrapf(err, "failed to make use of filesystem token")
		return client, err
	}

	if ok {
		return client, err
	}

	// No token, or the token is expired.  Try the various auth methods in order of preference
	for _, authMethod := range config.AuthMethods {
		client, err := authMethod.Authenticator(config)
		if err != nil {
			if config.Verbose {
				fmt.Printf("Auth method %s failed:%s\n", authMethod.Name, err)
			}

			continue
		}

		return client, err
	}

	err = errors.New("All auth methods have failed.\n")

	return client, err
}

func verboseOutput(verbose bool, message string, args ...interface{}) {
	if verbose {
		if len(args) == 0 {
			fmt.Printf("%s\n", message)
			return
		}

		msg := fmt.Sprintf(message, args...)
		fmt.Printf("%s\n", msg)
	}
}
