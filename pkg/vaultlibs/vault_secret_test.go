package vaultlibs

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestSecretsForRole(t *testing.T) {
	// TODO Implement TestSecretsForRole by uncommenting the code above, and adding some role/ policy data and fetch it to see if we're doing what we expect.
}

// TODO rework the following to use the vault test server
func testSecretPath() string {
	return "secret/testsecret"
}

func testSecretListPath() string {
	return "secret/manytestsecrets"
}

func testSecretListPath1() string {
	return "secret/manytestsecrets/SECRET1"
}

func testSecretListPath2() string {
	return "secret/manytestsecrets/SECRET2"
}

func testSecret1Name() string {
	return "SECRET1"
}

func testSecret2Name() string {
	return "SECRET2"
}

func testSecret1Value() string {
	return "fargle"
}

func testSecret2Value() string {
	return "goongala"
}

func testSecret() map[string]interface{} {
	secrets := make(map[string]interface{}, 0)

	secrets[testSecret1Name()] = testSecret1Value()
	secrets[testSecret2Name()] = testSecret2Value()

	return secrets
}

func testSecret2() map[string]interface{} {
	secrets := make(map[string]interface{}, 0)

	secrets[testSecret1Name()] = testSecret1Value()
	secrets[testSecret2Name()] = testSecret2Value()

	return secrets
}

func TestCrudSecrets(t *testing.T) {
	client := testVault.VaultTestClient()

	// assert no secrets exist
	secret, err := GetSecret(client, testSecretPath())
	if err != nil {
		log.Printf("Error looking for secrets: %s\n", err)
		t.Fail()
	}
	if secret != nil {
		fmt.Printf("Secret: %s", secret.Data)
		assert.True(t, len(secret.Data) == 0, "No test secrets should exist")
	}

	secret, err = ListSecrets(client, testSecretListPath())
	if err != nil {
		log.Printf("Error looking for secrets: %s\n", err)
		t.Fail()
	}
	if secret != nil {
		fmt.Printf("Secret: %s", secret.Data)
		assert.True(t, len(secret.Data) == 0, "No test secrets should exist")
	}

	// create secrets
	err = PutSecret(client, testSecretPath(), testSecret())
	if err != nil {
		fmt.Printf("Error creating secrets: %s\n", err)
		t.Fail()
	}

	err = PutSecret(client, testSecretListPath1(), testSecret())
	if err != nil {
		fmt.Printf("Error creating secrets: %s\n", err)
		t.Fail()
	}

	err = PutSecret(client, testSecretListPath2(), testSecret2())
	if err != nil {
		fmt.Printf("Error creating secrets: %s\n", err)
		t.Fail()
	}

	// retrieve secrets
	secret, err = GetSecret(client, testSecretPath())
	if err != nil {
		fmt.Printf("Error looking for secrets: %s\n", err)
		t.Fail()
	}

	assert.Equal(t, testSecret(), secret.Data, "Fetched secrets meet expectations.")

	secret, err = ListSecrets(client, testSecretListPath())
	if err != nil {
		fmt.Printf("Error looking for secrets: %s\n", err)
		t.Fail()
	}

	keys, ok := secret.Data["keys"]
	if ok {
		s, ok := keys.([]interface{})
		if ok {
			assert.True(t, len(s) == 2, "2 elements in secret list")
		} else {
			log.Printf("Failed to retrieve secret list")
			t.Fail()
		}
	} else {
		log.Printf("Failed to retrieve secret list")
		t.Fail()
	}

	// delete secrets
	err = DeleteSecrets(client, testSecretPath())
	if err != nil {
		fmt.Printf("Error deleting secret: %s\n", err)
		t.Fail()
	}

	err = DeleteSecrets(client, testSecretListPath1())
	if err != nil {
		fmt.Printf("Error deleting secret: %s\n", err)
		t.Fail()
	}

	err = DeleteSecrets(client, testSecretListPath2())
	if err != nil {
		fmt.Printf("Error deleting secret: %s\n", err)
		t.Fail()
	}

	// prove they're really gone
	secret, err = GetSecret(client, testSecretPath())
	if err != nil {
		fmt.Printf("Error looking for secrets: %s\n", err)
		t.Fail()
	}

	if secret != nil {
		assert.True(t, len(secret.Data) == 0, "No test secrets exist")
	}

	secret, err = ListSecrets(client, testSecretListPath())
	if err != nil {
		log.Printf("Error looking for secrets: %s\n", err)
		t.Fail()
	}
	if secret != nil {
		fmt.Printf("Secret: %s", secret.Data)
		assert.True(t, len(secret.Data) == 0, "No test secrets should exist")
	}
}
