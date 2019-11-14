package vaultlibs

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
)

// UseFSToken Attempts to use a Vault Token found on the filesystem.
func UseFSToken(client *api.Client, verbose bool) (ok bool, err error) {
	homeDir, err := homedir.Dir()
	if err != nil {
		err = errors.Wrap(err, "failed to get user's homedir")
		return ok, err
	}

	tokenFilePath := fmt.Sprintf("%s/%s", homeDir, VAULT_TOKEN_FILE)
	VerboseOutput(verbose, "Looking for a potential vault token at %s", tokenFilePath)

	if _, existErr := os.Stat(tokenFilePath); !os.IsNotExist(existErr) {
		VerboseOutput(verbose, "  It exists.")

		b, err := ioutil.ReadFile(tokenFilePath)
		if err != nil {
			err = errors.Wrapf(err, "failed to read token out of %s", tokenFilePath)
			return ok, err
		}

		token := string(b)
		client.SetToken(token) // set token

		if token == "" {
			VerboseOutput(verbose, "  token file has no content.")
			return ok, err
		}

		_, tokOkErr := client.Auth().Token().LookupSelf()
		if tokOkErr != nil {
			VerboseOutput(verbose, "  token is not valid.")
			// don't blow up, just return false, and let auth proceed
			return ok, err
		}

		VerboseOutput(verbose, "  token set.")

		err = RenewTokenIfStale(client, verbose)
		if err != nil {
			return ok, err
		}

		ok = true
		return ok, err
	}

	VerboseOutput(verbose, "  no token found.  Moving on to other auth methods.")

	return ok, err
}

// RenewTokenIfStale renews a Vault token if it happens to be near expiration.
func RenewTokenIfStale(client *api.Client, verbose bool) (err error) {
	// at this point, we have a token, either from the env or the filesystem.
	// renew the token, since it may be near expiration
	// don't really care about the error result of this call, as some tokens are not refreshable, and this is mostly a convenience feature so the user doesn't have to login.
	_, _ = client.Auth().Token().RenewSelf(0)

	return err
}
