package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/harnash/netatmo-trmnl/internal/netatmo"
	"github.com/harnash/netatmo-trmnl/internal/store"
	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	slogecho "github.com/samber/slog-echo"
	"golang.org/x/time/rate"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
)

type config struct {
	LogLevel     string `koanf:"TRMNL_LOG_LEVEL"`
	ServiceURL   string `koanf:"TRMNL_SERVICE_URL"`
	ServicePort  string `koanf:"TRMNL_SERVICE_PORT"`
	AuthURL      string `koanf:"TRMNL_AUTH_URL"`
	TokenURL     string `koanf:"TRMNL_TOKEN_URL"`
	ClientID     string `koanf:"TRMNL_CLIENT_ID"`
	ClientSecret string `koanf:"TRMNL_CLIENT_SECRET"`
	APIAuth      struct {
		AccessToken  string    `koanf:"ACCESS_TOKEN"`
		RefreshToken string    `koanf:"REFRESH_TOKEN"`
		TokenExpiry  time.Time `koanf:"TOKEN_EXPIRY"`
	} `koanf:"TRMNL_API_AUTH"`
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

func NewTemplateRegistry(logger *slog.Logger) (*TemplateRegistry, error) {
	templates := make(map[string]*template.Template)
	files, err := fs.Glob(resources, "public/views/*.html")
	if err != nil {
		return nil, errors.New("cannot open template files")
	}
	for _, tmplFile := range files {
		if tmplFile == "public/views/base.html" {
			continue
		}

		logger.With("template", tmplFile).Debug("parsing template file")

		templates[filepath.Base(tmplFile)] = template.Must(template.New(tmplFile).Funcs(
			template.FuncMap{
				"marshal": func(v interface{}) template.JS {
					a, _ := json.Marshal(v)
					return template.JS(a)
				},
			}).ParseFS(resources, tmplFile, "public/views/base.html"))
	}
	return &TemplateRegistry{
		templates: templates,
	}, nil
}

const AppName = "netatmo-trmnl"

// Global koanf instance. Use "." as the key path delimiter. This can be "/" or any character.
var k = koanf.New(".")

//go:embed public
var resources embed.FS

func ParseLevel(s string) (slog.Level, error) {
	var level slog.Level
	var err = level.UnmarshalText([]byte(s))
	return level, err
}

func main() {
	cfg := config{
		LogLevel: "info",
		AuthURL:  "https://api.netatmo.com/oauth2/authorize",
		TokenURL: "https://api.netatmo.com/oauth2/token",
	}

	// Load JSON config.
	if err := k.Load(file.Provider(".env"), dotenv.ParserEnv("TRMNL_", ".", nil)); err != nil {
		log.Fatalf("error loading config: %v", err)
	}

	if err := k.Load(env.Provider(".", env.Opt{Prefix: "TRMNL_"}), nil); err != nil {
		log.Fatalf("error loading env variables: %v", err)
	}

	if err := k.Unmarshal("", &cfg); err != nil {
		log.Fatalf("error unmarshaling config: %v", err)
	}

	ctx := context.Background()
	oauthConf := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       []string{"read_station", "read_thermostat"},
		RedirectURL:  fmt.Sprintf("%s:%s/redirect", cfg.ServiceURL, cfg.ServicePort),
		Endpoint: oauth2.Endpoint{
			AuthURL:   cfg.AuthURL,
			TokenURL:  cfg.TokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	dataStore, err := store.InitStore("")
	if err != nil {
		log.Fatal(err)
	}

	currentToken, err := dataStore.GetAccessToken(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		log.Info("no access token found in the datastore")
	} else if err != nil {
		log.Fatal(err)
	} else {
		cfg.APIAuth.AccessToken = currentToken
	}

	refreshToken, err := dataStore.GetRefreshToken(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		log.Info("no refresh token found in the datastore")
	} else if err != nil {
		log.Fatal(err)
	} else {
		cfg.APIAuth.RefreshToken = refreshToken
	}

	tokenExpiry, err := dataStore.GetTokenExpiry(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		log.Info("no token expiry found in the datastore")
	} else if err != nil {
		log.Fatal(err)
	} else {
		cfg.APIAuth.TokenExpiry = tokenExpiry
	}

	e := echo.New()

	var logLevel slog.Level
	if logLevel, err = ParseLevel(cfg.LogLevel); err != nil {
		log.Fatalf("invalid log level: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	e.Use(slogecho.New(logger))

	e.Renderer, err = NewTemplateRegistry(logger)
	if err != nil {
		log.Fatal(err)
	}

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
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}
		verifier := oauth2.GenerateVerifier()
		url := oauthConf.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))

		return c.Render(http.StatusOK, "authorize.html", map[string]interface{}{
			"loginLink": url,
		})
	})
	e.GET("/robots.txt", func(c echo.Context) error {
		return c.String(http.StatusOK, "User-agent: *\nDisallow: /")
	})
	e.GET("/dashboard", func(c echo.Context) error {
		src := []netatmo.Source{{
			StationName: "Dom",
			ModuleNames: []string{"balkon"},
		}}
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		measures, newToken, newRefreshToken, newExpiry, err := netatmo.FetchData(logger, src, cfg.ClientID, cfg.ClientSecret, cfg.APIAuth.AccessToken, cfg.APIAuth.RefreshToken, cfg.APIAuth.TokenExpiry)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while fetching data: %s", err.Error()))
		}
		if newToken != "" && newToken != cfg.APIAuth.AccessToken {
			cfg.APIAuth.AccessToken = newToken
			cfg.APIAuth.RefreshToken = newRefreshToken
			cfg.APIAuth.TokenExpiry = newExpiry
			err = dataStore.SetAccessToken(c.Request().Context(), newToken)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while storing new access token: %s", err.Error()))
			}
			err = dataStore.SetRefreshToken(c.Request().Context(), newRefreshToken)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while storing new refresh token: %s", err.Error()))
			}
			err = dataStore.SetTokenExpiry(c.Request().Context(), newExpiry)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while storing new token expiry: %s", err.Error()))
			}
		}
		if c.Request().Header.Get("Accept") == "application/json" {
			return c.JSON(http.StatusOK, measures)
		}
		return c.Render(http.StatusOK, "dashboard.html", map[string]interface{}{
			"currentData": measures,
		})
	})
	e.GET("/redirect", func(c echo.Context) error {
		if c.QueryParam("error") != "" {
			return echo.NewHTTPError(http.StatusBadRequest, c.QueryParam("error"))
		}
		exchangeCode := c.QueryParam("code")
		if exchangeCode == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing code query parameter")
		}
		token, err := oauthConf.Exchange(c.Request().Context(), exchangeCode, oauth2.AccessTypeOffline)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while exchanging code for token: %s", err.Error()))
		}
		err = dataStore.SetAccessToken(c.Request().Context(), token.AccessToken)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while storing access token: %s", err.Error()))
		}
		err = dataStore.SetRefreshToken(c.Request().Context(), token.RefreshToken)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while storing refresh token: %s", err.Error()))
		}
		err = dataStore.SetTokenExpiry(c.Request().Context(), token.Expiry)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while storing token expiry: %s", err.Error()))
		}

		cfg.APIAuth.AccessToken = token.AccessToken
		cfg.APIAuth.RefreshToken = token.RefreshToken
		cfg.APIAuth.TokenExpiry = token.Expiry

		return c.Redirect(http.StatusSeeOther, "/dashboard")
	})
	logger.With("url", cfg.ServiceURL, "port", cfg.ServicePort).Info("starting service")
	e.Logger.Fatal(e.Start(":" + cfg.ServicePort))
}
