package main

import "github.com/digitalocean/godo"
import "golang.org/x/oauth2"
import "context"
import "os"

var DoClient *godo.Client

type TokenSource struct {
	AccessToken string
}

func (t *TokenSource) Token() (*oauth2.Token, error) {
	token := &oauth2.Token{
		AccessToken: t.AccessToken,
	}
	return token, nil
}

func initDoClient() {

	pat := os.Getenv("TOKEN")

	tokenSource := &TokenSource{
		AccessToken: pat,
	}
	oauthClient := oauth2.NewClient(context.Background(), tokenSource)
	DoClient = godo.NewClient(oauthClient)
}

func provision(token, domain string) error {
	return nil
}

func unprovision(domain string) error {
	return nil
}
