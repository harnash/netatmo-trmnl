package main

import (
	"context"
	"errors"
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
	"path/filepath"
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

type TemplateRegistry struct {
	templates map[string]*template.Template
}

func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, ok := t.templates[name]
	if !ok {
		err := errors.New("Template not found -> " + name)
		return err
	}
	return tmpl.ExecuteTemplate(w, "base.html", data)
}

func NewTemplateRegistry() (*TemplateRegistry, error) {
	templates := make(map[string]*template.Template)
	files, err := filepath.Glob("public/views/*.html")
	if err != nil {
		return nil, errors.New("cannot open template files")
	}
	for _, tmplFile := range files {
		if tmplFile == "public/views/base.html" {
			continue
		}
		templates[filepath.Base(tmplFile)] = template.Must(template.ParseFiles(tmplFile, "public/views/base.html"))
	}
	return &TemplateRegistry{
		templates: templates,
	}, nil
}

const AppName = "netatmo-trmnl"

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

	currentToken, err := dataStore.GetAccessToken(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	cfg.APIAuth.AccessToken = currentToken

	e := echo.New()
	e.Renderer, err = NewTemplateRegistry()
	if err != nil {
		log.Fatal(err)
	}
	e.Logger.SetLevel(log.DEBUG)

	skipper := func(c echo.Context) bool {
		// Skip health check endpoint
		return c.Request().URL.Path == "/health"
	}
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Skipper: skipper,
	}))
	e.Use(echoprometheus.NewMiddleware(AppName)) // adds middleware to gather metrics
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
		if c.QueryParam("code") == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing code query parameter")
		}
		c.Logger().Infof("storing access token: %s", c.QueryParam("code"))
		err = dataStore.SetAccessToken(c.Request().Context(), c.QueryParam("code"))
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while storing access token: %s", err.Error()))
		}

		return c.Redirect(http.StatusSeeOther, "/setup")
	})
	e.Logger.Fatal(e.Start(":1323"))
}
