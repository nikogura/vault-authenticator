package vaultlibs

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/phayes/freeport"
	"github.com/scribd/vaulttest/pkg/vaulttest"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var tmpDir string
var testVault *vaulttest.VaultDevServer
var rootClient *api.Client

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
		os.Remove(tmpDir)
	}
	testVault.ServerShutDown()
}

func TestFileCopy(t *testing.T) {
	// TODO mock out a file and test that FileCopy actually copies it.
}

func TestDirCopy(t *testing.T) {
	// TODO mock out a directory and test that DirCopy actually copies it
}

func TestLocalUsername(t *testing.T) {
	username, err := LocalUsername()
	if err != nil {
		log.Printf("Error getting local user name: %s", err)
		t.Fail()
	}

	assert.True(t, username != "", "Local username returns something")
}
