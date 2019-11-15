package vaultlibs

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestSecretsForRole(t *testing.T) {
	// TODO Implement TestSecretsForRole by uncommenting the code above, and adding some role/ policy data and fetch it to see if we're doing what we expect.
}

func TestCrudSecrets(t *testing.T) {
	inputs := []struct {
		name   string
		path   string
		secret map[string]interface{}
	}{
		{
			"test1",
			"secret/data/testsecret1",
			map[string]interface{}{
				"SECRET1": "fargle",
			},
		},
		{
			"test2",
			"secret/data/testsecret2",
			map[string]interface{}{
				"SECRET2": "goongala",
			},
		},
	}

	client := testVault.VaultTestClient()

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {

			// assert the secret doesn't already exist
			s, err := GetSecret(client, tc.path)
			if err != nil {
				fmt.Printf("Error getting secret from path %s: %s", tc.path, err)
				t.Fail()
			}

			assert.True(t, s == nil, "Secret found where none should be")

			// Create it
			err = PutSecret(client, tc.path, tc.secret)
			if err != nil {
				fmt.Printf("Failed to put secret to path %s: %s", tc.path, err)
				t.Fail()
			}

			// prove it exists
			s, err = GetSecret(client, tc.path)
			if err != nil {
				fmt.Printf("Error getting secret from path %s: %s", tc.path, err)
				t.Fail()
			}

			assert.True(t, reflect.DeepEqual(s.Data["data"], tc.secret), "Secret failed to create")

			err = DeleteSecrets(client, tc.path)
			if err != nil {
				fmt.Printf("Failed deleting secrets at %s: %s", tc.path, err)
				t.Fail()
			}

			s, err = GetSecret(client, tc.path)
			if err != nil {
				fmt.Printf("Error getting secret from path %s: %s", tc.path, err)
				t.Fail()
			}

			// prove its gone
			s, err = GetSecret(client, tc.path)
			if err != nil {
				fmt.Printf("Error getting secret from path %s: %s", tc.path, err)
				t.Fail()
			}

			assert.True(t, s.Data["data"] == nil, "Secret failed to create")

		})
	}
}
