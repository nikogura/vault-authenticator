# vault-authenticator
[![Current Release](https://img.shields.io/github/release/nikogura/vault-authenticator.svg)](https://img.shields.io/github/release/nikogura/vault-authenticator.svg)

[![Circle CI](https://circleci.com/gh/nikogura/vault-authenticator.svg?style=shield)](https://circleci.com/gh/nikogura/vault-authenticator)

[![Go Report Card](https://goreportcard.com/badge/github.com/nikogura/vault-authenticator)](https://goreportcard.com/report/github.com/nikogura/vault-authenticator)

[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/nikogura/vault-authenticator/pkg/vault-authenticator)

[![Coverage Status](https://codecov.io/gh/nikogura/vault-authenticator/branch/master/graph/badge.svg)](https://codecov.io/gh/nikogura/vault-authenticator)

Useful golang functions for interacting with Vault.

Vault is a great tool, but programming against it sometimes requires one to go more deeply than one wants to in order to navigate these waters.

This library abstracts some of the work and provided some high level bindings so that the author of a tool that _uses_ Vault doesn't need to be an expert in Vault.

The crown jewel is the `authenticator` object which has has one main method: Auth().  This method tries to authenticate to Vault in a number of ways and returns an authenticated Vault client for the first one that succeeds.

## Configuration

To configure `authenticator`, create the object via it's constructor:

    auth = authenticator.NewAuthenticator()
    
    
Then set the address of the Vault server:

	auth.SetAddress("https://vault.example.com")
	
	
Set a private CA if you're using one:

	auth.SetCACertificate(`-----BEGIN CERTIFICATE-----
	...
    -----END CERTIFICATE-----
    `)


Set Auth methods.  These will be tried in order:

	auth.SetAuthMethods([]string{
		"iam",
		"k8s",
		"tls",
		"ldap",
	})
	
If your usernames don't necessarily map to posix users on the system:

	auth.SetUsernameFunc(somelib.GetUsername)
	

Finally, if using TLS Auth, set the locations of the client certs:

	auth.SetTlsClientCrtPath("/path/to/cert.crt")
	auth.SetTlsClientKeyPath("/path/to/key.key")
	
	
After that, simply run:

    client, err := auth.Auth()
    if err != nil {
      log.Fatalf("Auth failed: %s", err)
    }
    
    path := "/secret/foo
    
    secret, err := authenticator.GetSecret(client, path)
    if err != nil {
      log.Fatalf("Failed getting secret from %s: %s", path, err)
    }
    
    ... do something with secret ...
