package vaultlibs

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"strings"
)

// UserLogin logs the user into vault via LDAP and obtains a token.  (Really only intended for user usage)
func UserLogin(config *VaultConfig) (client *api.Client, err error) {
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

	client, err = api.NewClient(apiConfig)

	if config.Identifier == "" {
		err = errors.New("No username.  Cannot authenticate")
		return client, err
	}

	path := fmt.Sprintf("/auth/ldap/login/%s", config.Identifier)
	data := make(map[string]interface{})

	if config.Verbose {
		log.Printf("Username: %s", config.Identifier)
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
