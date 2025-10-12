package main

import (
	"fmt"
	"github.com/harnash/netatmo-trmnl/internal/store"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"golang.org/x/time/rate"
	"html/template"
	"io"
	"net/http"
	"os"
	"time"

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

type Template struct {
	templates *template.Template
}

const APP_NAME = "netatmo-trmnl"

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
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

	dataStore, err := store.InitStore("")
	if err != nil {
		log.Fatal(err)
	}

	e := echo.New()
	renderer := &Template{
		templates: template.Must(template.ParseGlob("public/views/*.html")),
	}
	e.Renderer = renderer

	skipper := func(c echo.Context) bool {
		// Skip health check endpoint
		return c.Request().URL.Path == "/health"
	}
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Skipper: skipper,
	}))
	e.Use(echoprometheus.NewMiddleware(APP_NAME)) // adds middleware to gather metrics
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(20))))
	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		StackSize: 1 << 10, // 1 KB
		LogLevel:  log.ERROR,
	}))
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		HSTSMaxAge:            3600,
		ContentSecurityPolicy: "default-src 'self'",
	}))
	e.Use(middleware.RequestID())
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))
	e.Use(middleware.ContextTimeout(30 * time.Second))
	e.Use(middleware.Decompress())
	e.Pre(middleware.RemoveTrailingSlash())

	// routes configuration
	e.GET("/health", func(c echo.Context) error { // basic healthcheck
		return c.String(http.StatusOK, "OK")
	})
	e.GET("/metrics", echoprometheus.NewHandler()) // adds route to serve gathered metrics
	e.GET("/", func(c echo.Context) error {
		if cfg.APIAuth.AccessToken != "" {

		}
		verifier := oauth2.GenerateVerifier()
		url := oauthConf.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))

		return c.Render(http.StatusOK, "authorize.html", map[string]interface{}{
			"loginLink": url,
		})
	})
	e.GET("/setup", func(c echo.Context) error {
		return c.String(http.StatusNotImplemented, "")
	})
	e.GET("/redirect", func(c echo.Context) error {
		if c.QueryParam("error") != "" {
			return echo.NewHTTPError(http.StatusBadRequest, c.QueryParam("error"))
		}
		err = dataStore.SetAccessToken(c.Request().Context(), c.Param("code"))
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while storing access token: %s", err.Error()))
		}

		return c.Redirect(http.StatusSeeOther, "/setup")
	})
	e.Logger.Fatal(e.Start(":1323"))
}
