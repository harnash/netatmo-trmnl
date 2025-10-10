package main

import (
	"fmt"
	"os"

	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

type config struct {
	AuthURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	APIAuth      struct {
		AccessToken  string
		RefreshToken string
	}
}

func main() {
	cfg := config{
		AuthURL:      "https://api.netatmo.com/oauth2/authorize",
		TokenURL:     "https://api.netatmo.com/oauth2/token",
		ClientID:     os.Getenv("NETATMO_CLIENT_ID"),
		ClientSecret: os.Getenv("NETATMO_CLIENT_SECRET"),
	}

	// ctx := context.Background()
	oauthConf := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       []string{"read_station", "read_thermostat"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthURL,
			TokenURL: cfg.TokenURL,
		},
	}

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		verifier := oauth2.GenerateVerifier()
		url := oauthConf.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))

		return c.HTML(200, fmt.Sprintf(`<a href="%s">Login</a>`, url))
	})
	e.GET("/redirect", func(c echo.Context) error {
		return c.HTML(200, "OK")
	})
	e.Logger.Fatal(e.Start(":1323"))
}
