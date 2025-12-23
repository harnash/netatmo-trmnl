package server

import (
	"fmt"
	"github.com/harnash/netatmo-trmnl/internal/netatmo"
	"github.com/harnash/netatmo-trmnl/internal/store"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"time"
)

type RoutesConfig struct {
	OAuthClientID     string
	OAuthClientSecret string
	AccessToken       string
	RefreshToken      string
	TokenExpiry       time.Time
	StationName       string
	ModulesNames      []string
}

func RegisterRoutes(e *echo.Echo, cfg *RoutesConfig, oauthConf *oauth2.Config, dataStore *store.DataStore, log *slog.Logger) {
	e.GET("/health", func(c echo.Context) error { // basic healthcheck
		return c.String(http.StatusOK, "OK")
	})
	e.GET("/metrics", echoprometheus.NewHandler()) // adds route to serve gathered metrics
	e.GET("/", func(c echo.Context) error {
		if cfg.AccessToken != "" {
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
	e.POST("/logout", func(c echo.Context) error {
		err := dataStore.DeleteTokens(c.Request().Context())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while deleting tokens: %s", err.Error()))
		}
		cfg.AccessToken = ""
		cfg.RefreshToken = ""
		cfg.TokenExpiry = time.Time{}
		return c.Redirect(http.StatusSeeOther, "/")
	})
	e.GET("/dashboard", func(c echo.Context) error {
		src := netatmo.Source{
			StationName: cfg.StationName,
			ModuleNames: cfg.ModulesNames,
		}
		measures, newToken, newRefreshToken, newExpiry, err := netatmo.FetchData(log, src, cfg.OAuthClientID, cfg.OAuthClientSecret, cfg.AccessToken, cfg.RefreshToken, cfg.TokenExpiry)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while fetching data: %s", err.Error()))
		}
		if newToken != "" && newToken != cfg.AccessToken {
			cfg.AccessToken = newToken
			cfg.RefreshToken = newRefreshToken
			cfg.TokenExpiry = newExpiry
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

		cfg.AccessToken = token.AccessToken
		cfg.RefreshToken = token.RefreshToken
		cfg.TokenExpiry = token.Expiry

		return c.Redirect(http.StatusSeeOther, "/dashboard")
	})
}
