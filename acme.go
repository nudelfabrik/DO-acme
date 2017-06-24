package main

import "golang.org/x/crypto/acme"
import "crypto/rsa"
import "crypto/rand"
import "crypto/ecdsa"
import "crypto/x509"
import "crypto/elliptic"
import "log"
import "context"

func request() (*ecdsa.PrivateKey, [][]byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	client := &acme.Client{Key: key}

	ctx := context.Background()
	a, err := client.Authorize(ctx, "example.com")
	if err != nil {
		log.Fatal(err)
	}
	if a.Status == acme.StatusValid {
		// Client.Key is already authorized for example.com.
		// Skip DNS record provisioning and go to client.CreateCert
	}

	// Find dns-01 challenge in a.Challenges.
	// Let's assume the var name is challenge.
	var challenge *acme.Challenge
	tok, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		log.Fatal(err)
	}
	// Provision tok value under _acme-challenge.example.com as a TXT record.
	// Remember to defer unprovision().
	provision(tok, "example.com")
	defer unprovision("example.com")
	// Once provisioned and propagated in DNS:
	if _, err := client.Accept(ctx, challenge); err != nil {
		log.Fatal(err)
	}
	a, err = client.WaitAuthorization(ctx, a.URI)
	if err != nil {
		log.Fatal(err)
	}
	if a.Status != acme.StatusValid {
		log.Fatal("domain authorization failed")
	}

	// Create the certificate.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	req := &x509.CertificateRequest{DNSNames: []string{"example.com"}} // populate other fields
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, priv)
	if err != nil {
		log.Fatal(err)
	}
	pub, _, err := client.CreateCert(ctx, csr, 0, true)
	if err != nil {
		log.Fatal(err)
	}

	// priv is now the private part of the cert.
	// pub is the public part (DER format), including the chain.
	return priv, pub

}
