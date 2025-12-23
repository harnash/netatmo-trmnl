package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/harnash/netatmo-trmnl/internal/server"
	"github.com/harnash/netatmo-trmnl/internal/store"
	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	gomlog "github.com/labstack/gommon/log"
	slogecho "github.com/samber/slog-echo"
	"golang.org/x/time/rate"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/natefinch/lumberjack.v2"
)

type config struct {
	LogLevel     string `koanf:"TRMNL_LOG_LEVEL"`
	LogFile      string `koanf:"TRMNL_LOG_FILE"`
	ServiceURL   string `koanf:"TRMNL_SERVICE_URL"`
	ServicePort  string `koanf:"TRMNL_SERVICE_PORT"`
	AuthURL      string `koanf:"TRMNL_AUTH_URL"`
	TokenURL     string `koanf:"TRMNL_TOKEN_URL"`
	ClientID     string `koanf:"TRMNL_CLIENT_ID"`
	ClientSecret string `koanf:"TRMNL_CLIENT_SECRET"`
	AuthToken    string `koanf:"TRMNL_AUTH_TOKEN"`
	APIAuth      struct {
		AccessToken  string    `koanf:"ACCESS_TOKEN"`
		RefreshToken string    `koanf:"REFRESH_TOKEN"`
		TokenExpiry  time.Time `koanf:"TOKEN_EXPIRY"`
	} `koanf:"TRMNL_API_AUTH"`
	Netatmo struct {
		StationName  string   `koanf:"STATION_NAME"`
		ModulesNames []string `koanf:"MODULES_NAMES"`
	} `koanf:"TRMNL_NETATMO"`
}

type TemplateRegistry struct {
	templates map[string]*template.Template
}

func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
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

	var log *slog.Logger
	log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, Level: slog.LevelInfo}))

	// Load JSON config.
	if err := k.Load(file.Provider(".env"), dotenv.ParserEnv("TRMNL_", ".", nil)); err != nil {
		log.Error("error loading config", slog.String("err", err.Error()))
		os.Exit(1)
	}

	if err := k.Load(env.Provider(".", env.Opt{Prefix: "TRMNL_"}), nil); err != nil {
		log.Error("error loading env variables", slog.String("err", err.Error()))
		os.Exit(2)
	}

	if err := k.Unmarshal("", &cfg); err != nil {
		log.Error("error unmarshaling config", slog.String("err", err.Error()))
		os.Exit(3)
	}

	var err error
	var logLevel slog.Level
	if logLevel, err = ParseLevel(cfg.LogLevel); err != nil {
		log.Error("invalid log level", slog.String("err", err.Error()))
		logLevel = slog.LevelInfo
	}

	if cfg.AuthToken == "" {
		log.Error("no auth token provided, please set TRMNL_AUTH_TOKEN environment variable or in the config file")
		os.Exit(4)
	}

	var logWriter io.Writer
	if cfg.LogFile != "" {
		logRotator := &lumberjack.Logger{
			Filename:   cfg.LogFile,
			MaxSize:    100,  // Max size in MB
			MaxBackups: 5,    // Number of backups
			MaxAge:     30,   // Days
			Compress:   true, // Enable compression
		}
		logWriter = io.MultiWriter(os.Stdout, logRotator)
	} else {
		logWriter = os.Stdout
	}

	log = slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
		AddSource: true,
		Level:     logLevel,
	}))

	log.Debug("configuration loaded", slog.Any("config", cfg))

	ctx := context.Background()
	var redirectURL string
	if cfg.ServicePort == "80" || cfg.ServicePort == "443" {
		redirectURL = fmt.Sprintf("%s/redirect", cfg.ServiceURL)
	} else {
		redirectURL = fmt.Sprintf("%s:%s/redirect", cfg.ServiceURL, cfg.ServicePort)
	}
	oauthConf := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       []string{"read_station", "read_thermostat"},
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:   cfg.AuthURL,
			TokenURL:  cfg.TokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	dataStore, err := store.InitStore("")
	if err != nil {
		log.Error("cannot initialize store", slog.String("err", err.Error()))
		os.Exit(5)
	}

	currentToken, err := dataStore.GetAccessToken(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		log.Info("no access token found in the datastore")
	} else if err != nil {
		log.Error("cannot fetch OAuth access token", slog.String("err", err.Error()))
		os.Exit(6)
	} else {
		cfg.APIAuth.AccessToken = currentToken
	}

	refreshToken, err := dataStore.GetRefreshToken(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		log.Info("no refresh token found in the datastore")
	} else if err != nil {
		log.Error("cannot fetch OAuth refresh token", slog.String("err", err.Error()))
		os.Exit(7)
	} else {
		cfg.APIAuth.RefreshToken = refreshToken
	}

	tokenExpiry, err := dataStore.GetTokenExpiry(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		log.Info("no token expiry found in the datastore")
	} else if err != nil {
		log.Error("cannot fetch token expiry", slog.String("err", err.Error()))
		os.Exit(8)
	} else {
		cfg.APIAuth.TokenExpiry = tokenExpiry
	}

	e := echo.New()
	e.Use(slogecho.New(log))
	e.Use(middleware.RequestID())

	e.Renderer, err = NewTemplateRegistry(log)
	if err != nil {
		log.Error("", slog.String("err", err.Error()))
		os.Exit(9)
	}

	e.Use(echoprometheus.NewMiddleware(AppName)) // adds middleware to gather metrics
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(20))))
	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		StackSize: 1 << 10, // 1 KB
		LogLevel:  gomlog.ERROR,
	}))
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		HSTSMaxAge:            3600,
		ContentSecurityPolicy: "default-src 'self'",
	}))
	e.Use(middleware.KeyAuth(func(key string, c echo.Context) (bool, error) {
		if key == cfg.AuthToken {
			return true, nil
		}
		return false, nil
	}))
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))
	e.Use(middleware.ContextTimeout(30 * time.Second))
	e.Use(middleware.Decompress())
	e.Pre(middleware.RemoveTrailingSlash())

	// routes configuration
	routesConfig := &server.RoutesConfig{
		OAuthClientID:     cfg.ClientID,
		OAuthClientSecret: cfg.ClientSecret,
		AccessToken:       cfg.APIAuth.AccessToken,
		RefreshToken:      cfg.APIAuth.RefreshToken,
		TokenExpiry:       cfg.APIAuth.TokenExpiry,
		StationName:       cfg.Netatmo.StationName,
		ModulesNames:      cfg.Netatmo.ModulesNames,
	}
	server.RegisterRoutes(e, routesConfig, oauthConf, dataStore, log)

	log.Info("starting service", slog.String("url", cfg.ServiceURL), slog.String("port", cfg.ServicePort))
	e.Logger.Fatal(e.Start(":" + cfg.ServicePort))
}
