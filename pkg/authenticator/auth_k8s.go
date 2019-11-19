package authenticator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

const DEFAULT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// K8sLogin Login to Vault from a K8s pod.
func K8sLogin(authenticator *Authenticator) (client *api.Client, err error) {
	if _, err := os.Stat(DEFAULT_TOKEN_PATH); os.IsNotExist(err) {
		err = errors.New("No JWT token found.  K8S login impossible.")
		return client, err
	}

	verboseOutput(authenticator.Verbose, "Attempting K8s Login...")

	if authenticator.Identifier == "" {
		err = errors.New("supplied cluster name is blank- cannot auth")
		return client, err
	}

	verboseOutput(authenticator.Verbose, "  to cluster %q...", authenticator.Identifier)

	apiConfig, err := ApiConfig(authenticator.Address, authenticator.CACertificate)
	if err != nil {
		err = errors.Wrap(err, "failed creating vault api config")
	}

	jwtBytes, err := ioutil.ReadFile(DEFAULT_TOKEN_PATH)
	if err != nil {
		err = errors.Wrapf(err, "failed to read token from %s", DEFAULT_TOKEN_PATH)
		return client, err
	}

	verboseOutput(authenticator.Verbose, "  successfully read k8s JWT token in pod")

	//curl -X POST -H "Content-type: application/json" https://vault-prod.inf.scribd.com:8200/v1/auth/k8s-bravo/login -d '{"role": "test-role", "jwt":”<jwt of principal>”}'
	data := map[string]string{
		"role": authenticator.Role,
		"jwt":  string(jwtBytes),
	}

	postdata, err := json.Marshal(data)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal data in auth request")
		return client, err
	}

	vaultAddress := authenticator.Address
	// protect potential double slashes
	vaultAddress = strings.TrimRight(vaultAddress, "/")

	vaultUrl := fmt.Sprintf("%s/v1/auth/k8s-%s/login", vaultAddress, authenticator.Identifier)

	verboseOutput(authenticator.Verbose, "  vault url is %s", vaultUrl)
	verboseOutput(authenticator.Verbose, "  making request...")

	resp, err := http.Post(vaultUrl, "application/json", bytes.NewBuffer(postdata))
	if err != nil {
		err = errors.Wrapf(err, "failed to post auth data to vault")
		return client, err
	}

	verboseOutput(authenticator.Verbose, "  Response code: %d", resp.StatusCode)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrapf(err, "failed to read auth response body")
		return client, err
	}

	var authData map[string]interface{}

	err = json.Unmarshal(body, &authData)
	if err != nil {
		err = errors.Wrapf(err, "failed to unmarshal data in response body")
		return client, err
	}

	authError, ok := authData["errors"].([]interface{})
	if ok {
		if len(authError) > 0 {
			err = errors.New(fmt.Sprintf("error authenticating to vault: %s", authError[0]))
			return client, err
		}

		err = errors.New("unknown err authenticating to vault")
		return client, err
	}

	auth, ok := authData["auth"].(map[string]interface{})
	if !ok {
		err = errors.New("failed to get auth data from response")
		return client, err
	}

	verboseOutput(authenticator.Verbose, "  auth data successfully parsed")

	token, ok := auth["client_token"].(string)
	if !ok {
		err = errors.New("returned client token is not a string")
		return client, err
	}

	verboseOutput(authenticator.Verbose, "  vault token extracted")

	client, err = api.NewClient(apiConfig)
	if err != nil {
		err = errors.Wrapf(err, "failed to create vault client from authenticator")
		return client, err
	}

	client.SetToken(token)

	verboseOutput(authenticator.Verbose, "Success!\n")

	return client, err
}

/*
	sample auth response
{
  "request_id": "eb4685e0-e098-03be-2a5c-17bbd0f15b46",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": null,
  "wrap_info": null,
  "warnings": null,
  "auth": {
    "client_token": "s.G4mHd9INCGvOI2TX9xq5DLH2",
    "accessor": "xvJdPfs0KHC3d3yWrgx9ef8z",
    "policies": [
      "default",
      "prod-testns1-app1"
    ],
    "token_policies": [
      "default",
      "prod-testns1-app1"
    ],
    "metadata": {
      "role": "testns1-app1",
      "service_account_name": "default",
      "service_account_namespace": "testns1",
      "service_account_secret_name": "default-token-gzck4",
      "service_account_uid": "fcfa412e-3ec3-4162-921e-fb33488a2f5c"
    },
    "lease_duration": 2764800,
    "renewable": true,
    "entity_id": "ec4ae0c2-8b4f-2a04-73c2-bcb7215f4331",
    "token_type": "service",
    "orphan": true
  }
}
*/
