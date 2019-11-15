package vaultlibs

import (
	tls2 "crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"strings"
)

const CLIENT_CERT_PATH = "/etc/vault/host.crt"
const CLIENT_KEY_PATH = "/etc/vault/host.key"
const VAULT_TOKEN_FILE = ".vault-token"
const DEFAULT_VAULT_ADDR = "https://vault.corp.scribd.com"
const VAULT_TOKEN_ENV_VAR = "VAULT_TOKEN"
const SCRIBD_ROOT_CA_CERT = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

const VAULT_AUTH_FAIL = "vault login fail.  It didn't blow up, but also didn't return a token, either."

// VaultConfig creates a new config for vault, sets VAULT_ADDR if it's not already set, and adds the scribd root CA cert to the trust store.
func VaultConfig() (config *api.Config, err error) {
	// read the environment and use that over anything
	config = api.DefaultConfig()

	err = config.ReadEnvironment()
	if err != nil {
		err = errors.Wrapf(err, "failed to inject environment into client config")
		return config, err
	}

	if config.Address == "https://127.0.0.1:8200" {
		config.Address = DEFAULT_VAULT_ADDR
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		err = errors.Wrapf(err, "failed to get system cert pool")
		return config, err
	}

	ok := rootCAs.AppendCertsFromPEM([]byte(SCRIBD_ROOT_CA_CERT))
	if !ok {
		err = errors.New("Failed to add scribd root cert to system CA bundle")
		return config, err
	}

	clientConfig := &tls2.Config{
		RootCAs: rootCAs,
	}

	config.HttpClient.Transport = &http.Transport{TLSClientConfig: clientConfig}

	return config, err
}

// VaultAuth Authenticates to Vault by a number of methods.  K8s is preferred, but if that fails, it tries AWS, TLS, and finally LDAP
func VaultAuth(rolename string, k8sCluster string, prompt bool, verbose bool) (client *api.Client, err error) {
	config, err := VaultConfig()

	client, err = api.NewClient(config)
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
	ok, err := UseFSToken(client, verbose)
	if err != nil {
		err = errors.Wrapf(err, "failed to make use of filesystem token")
		return client, err
	}

	if ok {
		return client, err
	}

	k8s := make(chan bool)
	aws := make(chan bool)
	tls := make(chan bool)

	go DetectK8s(k8s, verbose)
	go DetectAws(aws, verbose)
	go DetectTls(tls, verbose)

	isK8s := <-k8s
	isAws := <-aws
	isTls := <-tls

	if isAws {
		return IAMLogin(rolename, verbose)
	} else if isK8s {
		return K8sLogin(k8sCluster, rolename, verbose)
	} else if isTls {
		return TLSLogin(rolename, verbose)
	}

	if prompt {
		// LDAP Login
		if verbose {
			log.Printf("Attempting User login via LDAP...\n\n")
		}
		return UserLogin(verbose)
	}

	return client, err
}

// UserLogin logs the user into vault via LDAP and obtains a token.  (Really only intended for user usage)
func UserLogin(verbose bool) (client *api.Client, err error) {
	config, err := VaultConfig()
	client, err = api.NewClient(config)

	userConfig, err := LoadUserConfig()
	if err != nil {
		err = errors.Wrapf(err, "failed to load user config")
		return client, err
	}

	var username string

	if userConfig.Username != "" {
		username = userConfig.Username
	} else {
		userObj, err := user.Current()
		if err != nil {
			err = errors.Wrapf(err, "failed to get current user")
			return client, err
		}

		username = userObj.Username
	}

	path := fmt.Sprintf("/auth/ldap/login/%s", username)
	data := make(map[string]interface{})

	if verbose {
		log.Printf("Username: %s", username)
	}

	fmt.Println("")
	fmt.Printf("Enter Your LDAP password\n")

	passwordBytes, err := terminal.ReadPassword(0)
	if err != nil {
		err = errors.Wrapf(err, "failed to read password from terminal")
		return client, err
	}

	passwordString := string(passwordBytes)
	passwordString = strings.TrimSuffix(passwordString, "\n")

	data["password"] = passwordString

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		err = errors.Wrapf(err, "failed submitting auth data to vault")
		return client, err
	}

	if resp != nil {
		auth := resp.Auth
		token := auth.ClientToken

		if token != "" {
			client.SetToken(token)
			homeDir, err := homedir.Dir()
			if err != nil {
				err = errors.Wrapf(err, "failed to derive user home dir")
				return client, err
			}

			tokenFile := fmt.Sprintf("%s/%s", homeDir, VAULT_TOKEN_FILE)

			// write the token to the filesystem where expected for future use
			err = ioutil.WriteFile(tokenFile, []byte(token), 0644)
			if err != nil {
				err = errors.Wrapf(err, "failed to write token file: %s", tokenFile)
				return client, err
			}

			return client, err
		}
	}

	err = errors.New(VAULT_AUTH_FAIL)

	return client, err
}
