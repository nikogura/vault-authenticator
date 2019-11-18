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

// Authenticator What handles the authentication to Vault- by whatever supported methods you configure.  Authenticator will try them in order and return the first one that is successful.
type Authenticator struct {
	Address       string
	CACertificate string
	Prompt        bool
	Verbose       bool
	AuthMethods   []string
	Identifier    string
	Role          string
}

func (a *Authenticator) SetAddress(address string) {
	a.Address = address
}

func (a *Authenticator) SetCACertificate(certificate string) {
	a.CACertificate = certificate
}

func (a *Authenticator) SetPrompt(prompt bool) {
	a.Prompt = prompt
}

func (a *Authenticator) SetVerbose(verbose bool) {
	a.Verbose = verbose
}

func (a *Authenticator) SetAuthMethods(methods []string) {
	a.AuthMethods = methods
}

func (a *Authenticator) SetIdentifier(identifier string) {
	a.Identifier = identifier
}

func (a *Authenticator) SetRole(role string) {
	a.Role = role
}

// VaultAuth Authenticates to Vault by a number of methods.  AWS IAM is preferred, but if that fails, it tries K8s, TLS, and finally LDAP
func (a *Authenticator) Auth() (client *api.Client, err error) {
	// read the environment and use that over anything
	apiConfig := api.DefaultConfig()

	err = apiConfig.ReadEnvironment()
	if err != nil {
		err = errors.Wrapf(err, "failed to inject environment into client config")
		return client, err
	}

	if apiConfig.Address == "https://127.0.0.1:8200" {
		if a.Address != "" {
			apiConfig.Address = a.Address
		}
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		err = errors.Wrapf(err, "failed to get system cert pool")
		return client, err
	}

	if a.CACertificate != "" {
		ok := rootCAs.AppendCertsFromPEM([]byte(a.CACertificate))
		if !ok {
			err = errors.New("Failed to add scribd root cert to system CA bundle")
			return client, err
		}
	}

	clientConfig := &tls2.Config{
		RootCAs: rootCAs,
	}

	apiConfig.HttpClient.Transport = &http.Transport{TLSClientConfig: clientConfig}

	if a.Verbose {
		fmt.Printf("Vault Address: %s\n", apiConfig.Address)
		if a.CACertificate != "" {
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
	ok, err := UseFSToken(client, a.Verbose)
	if err != nil {
		err = errors.Wrapf(err, "failed to make use of filesystem token")
		return client, err
	}

	if ok {
		return client, err
	}

	// No token, or the token is expired.  Try the various auth methods in order of preference
	for _, authMethod := range a.AuthMethods {
		switch authMethod {
		case "iam":
			client, err = IAMLogin(a)
			if err != nil {
				if a.Verbose {
					fmt.Printf("Auth method %s failed:%s\n", authMethod, err)
				}

				continue
			}

			return client, err

		case "k8s":
			client, err = K8sLogin(a)
			if err != nil {
				if a.Verbose {
					fmt.Printf("Auth method %s failed:%s\n", authMethod, err)
				}

				continue
			}

			return client, err

		case "tls":
			client, err = TLSLogin(a)
			if err != nil {
				if a.Verbose {
					fmt.Printf("Auth method %s failed:%s\n", authMethod, err)
				}

				continue
			}

			return client, err

		case "ldap":
			client, err = LDAPLogin(a)
			if err != nil {
				if a.Verbose {
					fmt.Printf("Auth method %s failed:%s\n", authMethod, err)
				}

				continue
			}

			return client, err

		default:
			err = errors.New(fmt.Sprintf("Unknown auth type %s", authMethod))
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
