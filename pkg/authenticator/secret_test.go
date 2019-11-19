package authenticator

import (
	"fmt"
	"github.com/phayes/freeport"
	"github.com/scribd/vaulttest/pkg/vaulttest"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"testing"
)

var tmpDir string
var testVault *vaulttest.VaultDevServer

func TestMain(m *testing.M) {
	setUp()

	code := m.Run()

	tearDown()

	os.Exit(code)
}

func setUp() {
	dir, err := ioutil.TempDir("", "vaultlibs")
	if err != nil {
		fmt.Printf("Error creating temp dir %q: %s\n", tmpDir, err)
		os.Exit(1)
	}

	tmpDir = dir

	port, err := freeport.GetFreePort()
	if err != nil {
		log.Fatalf("Failed to get a free port on which to run the test vault server: %s", err)
	}

	testAddress := fmt.Sprintf("127.0.0.1:%d", port)

	testVault = vaulttest.NewVaultDevServer(testAddress)

	if !testVault.Running {
		testVault.ServerStart()

		// Create normal Secret engines
		client := testVault.VaultTestClient()

		// 'secret' already exists.  Leaving this commented out code just in case we need to add a second one later
		//for _, endpoint := range []string{
		//	"secret",
		//} {
		//	data := map[string]interface{}{
		//		"type":        "kv-v1",
		//		"description": "Secrets",
		//	}
		//	_, err := client.Logical().Write(fmt.Sprintf("sys/mounts/%s", endpoint), data)
		//	if err != nil {
		//		log.Fatalf("Unable to create secret engine %q: %s", endpoint, err)
		//	}
		//}

		// Create PKI Engine
		data := map[string]interface{}{
			"type":        "pki",
			"description": "PKI backend",
		}
		_, err := client.Logical().Write("sys/mounts/service", data)
		if err != nil {
			log.Fatalf("Failed to create 'service' pki secrets engine: %s", err)
		}

		data = map[string]interface{}{
			"common_name": "test-ca",
			"ttl":         "43800h",
		}
		_, err = client.Logical().Write("service/root/generate/internal", data)
		if err != nil {
			log.Fatalf("Failed to create root cert: %s", err)
		}
	}
}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		_ = os.Remove(tmpDir)
	}
	testVault.ServerShutDown()
}

func TestSecretsForRole(t *testing.T) {
	// TODO Implement TestSecretsForRole by uncommenting the code above, and adding some role/ policy data and fetch it to see if we're doing what we expect.
}

// TODO need tests for GetSecrets

// TODO need tests for ListSecrets

// TODO need tests for CopySecrets

// TODO need tests for MoveSecrets

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
