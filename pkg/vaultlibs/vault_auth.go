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

const VAULT_TOKEN_ENV_VAR = "VAULT_TOKEN"
const VAULT_AUTH_FAIL = "vault login fail.  It didn't blow up, but also didn't return a token, either."

// VaultSiteConfig A struct for setting fundamental information about how your org connects to Vault without needing to set ENV vars everywhere.  ENV Vars will still trump this value, but in their absence, this is a sane default for your org.
type VaultSiteConfig struct {
	Address       string
	CACertificate string
}

var VAULT_SITE_CONFIG VaultSiteConfig

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
		if VAULT_SITE_CONFIG.Address != "" {
			config.Address = VAULT_SITE_CONFIG.Address
		}
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		err = errors.Wrapf(err, "failed to get system cert pool")
		return config, err
	}

	if VAULT_SITE_CONFIG.CACertificate != "" {
		ok := rootCAs.AppendCertsFromPEM([]byte(VAULT_SITE_CONFIG.CACertificate))
		if !ok {
			err = errors.New("Failed to add scribd root cert to system CA bundle")
			return config, err
		}
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

	if verbose {
		fmt.Printf("Vault Address: %s\n", config.Address)
		if VAULT_SITE_CONFIG.CACertificate != "" {
			fmt.Printf("Private CA Cert in use.\n")
		}
	}

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

			tokenFile := fmt.Sprintf("%s/%s", homeDir, DEFAULT_VAULT_TOKEN_FILE)

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
