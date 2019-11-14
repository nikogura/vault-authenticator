package vaultlibs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var TLSSecretKeys = []string{
	"private_key",
	"certificate",
	"issuing_ca",
	"serial_number",
	"ca_chain",
	"private_key_type",
	"expiration",
}

var TLSSecretKeyAbbrev = map[string]string{
	"private_key":      "key",
	"certificate":      "crt",
	"issuing_ca":       "ca",
	"serial_number":    "serial",
	"ca_chain":         "chain",
	"private_key_type": "type",
	"expiration":       "expiration",
}

var TLSSecretBase64 = map[string]bool{
	"private_key":      true,
	"certificate":      true,
	"issuing_ca":       true,
	"serial_number":    false,
	"ca_chain":         true,
	"private_key_type": false,
	"expiration":       false,
}

var RSASecretKeys = []string{
	"unimplemented",
}

// SecretsForRole takes a role name and gets all secrets for that role in the current environment.
func SecretsForRole(client *api.Client, role string, env string, verbose bool) (data map[string]interface{}, err error) {
	data = make(map[string]interface{})
	var haveExplicitAccess bool
	var policy string

	VerboseOutput(verbose, "Looking for secrets for %s\n", role)

	// check the policies we can look up based on our token, see if we can get the role requested
	t, err := client.Auth().Token().LookupSelf()
	if t == nil {
		err = errors.Wrapf(err, "failed looking up policies for this token")
		return data, err
	}

	policies, ok := t.Data["policies"].([]interface{})
	if ok {
		VerboseOutput(verbose, "Policies:")
		for _, p := range policies {
			VerboseOutput(verbose, "  %s", p)
			pname, ok := p.(string)
			if ok {
				if strings.HasPrefix(pname, role) {
					haveExplicitAccess = true
					policy = pname
					VerboseOutput(verbose, "\n  Using policy %s\n\n", role)
					break
				}
			}
		}
	}

	// A principal has explicit access if the token for the principal has the name of the env-ns-role in it's list of policies.
	// This is the normal use case for application usage.
	// For LDAP users, it will not be the case, as ldap users have blanket access to dev/*.
	// In this case, the dev environment is assumed, and we just try to read all the secrets, returning an error if it ever fails.
	if !haveExplicitAccess {
		if env != "" {
			policy = fmt.Sprintf("%s-%s", role, env)
			VerboseOutput(verbose, "Environment explicitly overwritten.  This will fail unless principal has admin access.")

		} else {
			policy = fmt.Sprintf("%s-development", role)

			VerboseOutput(verbose, "This principal does not have explicit access to role %q\nAssuming development environment\n\n", role)
		}
	}

	paths := make([]string, 0)

	policyPath := fmt.Sprintf("sys/policy/%s", policy)

	// look up paths at policy
	s, err := client.Logical().Read(policyPath)
	if err != nil {
		err = errors.Wrapf(err, "failed looking up policy: %s", policy)
		return data, err
	}

	if s == nil {
		err = errors.New(fmt.Sprintf("no policy at %s", policyPath))
		return data, err
	}

	// find all paths we have there
	rules, ok := s.Data["rules"].(string)
	if ok {
		var rulesObj map[string]interface{}
		err := json.Unmarshal([]byte(rules), &rulesObj)
		if err != nil {
			err = errors.Wrapf(err, "failed to unmarshal rules string into json")
			return data, err
		}

		sysPatt := regexp.MustCompile(`sys/*`)

		rules, ok := rulesObj["path"].(map[string]interface{})
		if ok {
			for path, _ := range rules {
				if !sysPatt.MatchString(path) {
					paths = append(paths, path)
				}
			}
		}
	}

	// too complicated to use VerboseOutput()
	if verbose {
		fmt.Printf("Fetching secrets from the following paths:\n")
		for _, path := range paths {
			fmt.Printf("  %s\n", path)
		}

		fmt.Print("\n")
	}

	// get 'em all and return
	for _, path := range paths {
		VerboseOutput(verbose, "Reading path: %s", path)
		s, err := client.Logical().Read(path)
		if err != nil {
			err = errors.Wrapf(err, "Failed to lookup policy: %s", policy)
			return data, err
		}

		if s != nil {
			secretData, ok := s.Data["data"].(map[string]interface{})
			if ok {
				VerboseOutput(verbose, "  ... it's a v2 secret")
				// a v2 secret will have a key called 'value' if it's a bare secret
				// expected output key will be the name of the secret
				value, ok := secretData["value"]
				if ok {
					VerboseOutput(verbose, "    ... and a normal v2 secret")
					// get the dir portion of the path, cos the end is the environment
					dir := filepath.Dir(path)
					// get the base of that path, which will be the key
					key := filepath.Base(dir)
					data[key] = fmt.Sprintf("%s", value)
				} else { // else it's something special like a TLS Cert/Key
					VerboseOutput(verbose, "    ... and not a normal v2 secret")

					if HasKeys("tls", TLSSecretKeys, secretData, verbose) {
						VerboseOutput(verbose, "    ... it's a TLS Cert")
						keyBase := filepath.Base(path)
						for _, key := range TLSSecretKeys {
							keyName := fmt.Sprintf("%s.%s", keyBase, TLSSecretKeyAbbrev[key])
							v, ok := secretData[key]
							if ok {
								value, ok := v.(string)
								if ok {
									if TLSSecretBase64[key] {
										data[keyName] = base64.StdEncoding.EncodeToString([]byte(value))
									} else {
										data[keyName] = value
									}
								}
							}
						}

						//} else if HasKeys("rsa", RSASecretKeys, secretData, verbose) {
						//	// TODO Implement RSA Key type
					} else {
						err = errors.New(fmt.Sprintf("Undecipherable secret at path %s", path))
						return data, err
					}
				}
			} else {
				VerboseOutput(verbose, "  ... it's a v1 secret")
				// v1 secrets expect all keys to be here
				for k, v := range s.Data {
					data[k] = v
				}
			}
		}

		VerboseOutput(verbose, "\n\n")
	}

	return data, err
}

func HasKeys(typename string, keys []string, data map[string]interface{}, verbose bool) bool {
	VerboseOutput(verbose, "Checking Secret to see if it's a %s", typename)

	for _, key := range keys {
		VerboseOutput(verbose, "  ... Looking for %s", key)
		_, ok := data[key]
		if !ok {
			VerboseOutput(verbose, "  Failed to find %s.  Returning False.", key)
			return false
		}
	}

	VerboseOutput(verbose, "  Returning true.")

	return true
}

// EditSecret pulls the secret from the path given, and pops open $EDITOR to edit said secret.  When you save and close $EDITOR the secret is written back to vault.
func EditSecret(client *api.Client, path string) (err error) {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "nano"
	}

	command, err := exec.LookPath(editor)
	if err != nil {
		fmt.Printf("Command %q not found: %s", editor, err)
		os.Exit(1)
	}

	tmpFile, err := ioutil.TempFile("", "secretfile")
	if err != nil {
		fmt.Printf("Error creating temp file: %s", err)
		os.Exit(1)
	}

	secret, err := GetSecret(client, path)
	if err != nil {
		err = errors.Wrapf(err, "failed getting path %s", path)
		return err
	}

	var fetchedSecretOutput string

	if secret != nil {
		for k, v := range secret.Data {
			fetchedSecretOutput += fmt.Sprintf("%s: %s\n", k, v)
		}
	}

	err = ioutil.WriteFile(tmpFile.Name(), []byte(fmt.Sprintf(secretTemplate(), path, fetchedSecretOutput)), 0644)
	if err != nil {
		err = errors.Wrapf(err, "failed writing secret temp file %s", tmpFile.Name())
		return err
	}

	defer os.Remove(tmpFile.Name())

	shellenv := os.Environ()

	cmd := exec.Command(command, tmpFile.Name())

	cmd.Env = shellenv

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err = cmd.Start()
	if err != nil {
		fmt.Printf("Error starting command: %s", err)
		os.Exit(1)
	}

	err = cmd.Wait()
	if err != nil {
		fmt.Printf("Error waiting for command: %s", err)
		os.Exit(1)
	}

	contents, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		fmt.Printf("Error reading file: %s", err)
		os.Exit(1)
	}

	newSecret := make(map[string]interface{}, 0)

	err = yaml.Unmarshal(contents, &newSecret)
	if err != nil {
		err = errors.New("Unsupported syntax in secret file.  Only simple string key: value pairs are supported.")
		return err
	}

	err = PutSecret(client, path, newSecret)

	return err
}

// GetSecret returns a secret from the given path
func GetSecret(client *api.Client, path string) (secret *api.Secret, err error) {
	secret, err = client.Logical().Read(path)
	if err != nil {
		err = errors.Wrapf(err, "failed to fetch secret from %s", path)
		return secret, err
	}

	return secret, err
}

// GetSecrets gets all secrets at a given path.  Similar to ListSecrets, but returns the secret objects below path.
func GetSecrets(client *api.Client, paths []string) (secrets []*api.Secret, err error) {
	secrets = make([]*api.Secret, 0)

	for _, path := range paths {
		secret, err := GetSecret(client, path)
		if err != nil {
			err = errors.Wrapf(err, "failed to fetch secret from path %s", path)
		}

		if secret != nil {
			secrets = append(secrets, secret)
		}
	}

	return secrets, err
}

// ListSecrets runs a list on the path given.
func ListSecrets(client *api.Client, path string) (secret *api.Secret, err error) {
	secret, err = client.Logical().List(path)
	if err != nil {
		err = errors.Wrapf(err, "failed to list secrets from path %s", path)
		return secret, err
	}

	return secret, err
}

// PutSecret writes a secret to a path
func PutSecret(client *api.Client, path string, data map[string]interface{}) (err error) {
	_, err = client.Logical().Write(path, data)
	if err != nil {
		err = errors.Wrapf(err, "failed writing to %s", path)
	}

	return err
}

// CopySecret copies a secret from path A to path B
func CopySecret(client *api.Client, oldpath string, newpath string) (err error) {
	secret, err := GetSecret(client, oldpath)
	if err != nil {
		err = errors.Wrapf(err, "failed to get secret")
		return err
	}

	err = PutSecret(client, newpath, secret.Data)
	if err != nil {
		err = errors.Wrapf(err, "failed to put secret")
		return err
	}

	return err
}

// MoveSecret moves a secret from path A to path B
func MoveSecret(client *api.Client, oldpath string, newpath string) (err error) {
	err = CopySecret(client, oldpath, newpath)
	if err != nil {
		err = errors.Wrapf(err, "failed to copy secret")
	}

	err = DeleteSecrets(client, oldpath)
	if err != nil {
		err = errors.Wrapf(err, "failed to delete secret from original location")
	}

	return err
}

// DeleteSecrets  Deletes secrets at path given
func DeleteSecrets(client *api.Client, path string) (err error) {
	_, err = client.Logical().Delete(path)
	if err != nil {
		err = errors.Wrapf(err, "failed deleting %s", path)
	}

	return err
}

// secretTemplate  template for new secrets.
func secretTemplate() string {
	return `#
# secrets for %s
#
# Enter the secrets for your portal below in YAML format
# These should take the form of key-value string pairs.
# More complex secrets are not currently supported.
#
# Example:
# foo: bar
# baz: wip
#
# When you're done, save your work and close the editor and the information will be populated to Vault.
#

%s
`
}
