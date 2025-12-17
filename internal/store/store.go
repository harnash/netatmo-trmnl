package store

import (
	"context"
	"database/sql"
	"github.com/harnash/netatmo-trmnl/internal/store/db"
	"github.com/pkg/errors"
	_ "modernc.org/sqlite"
	"time"
)

const defaultDSN = "netatmo-trmnl.sqlite3"

type DataStore struct {
	query *db.Queries
}

func InitStore(dsn string) (*DataStore, error) {
	if dsn == "" {
		dsn = defaultDSN
	}
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errors.Wrap(err, "cannot open DB connection")
	}

	return &DataStore{query: db.New(sqlDB)}, nil
}

const accessTokenKey = "access_token"
const refreshTokenKey = "refresh_token"
const tokenExpiry = "token_expiry"

func (s *DataStore) SetAccessToken(ctx context.Context, token string) error {
	return s.query.SetConfigValue(ctx, db.SetConfigValueParams{Key: accessTokenKey, Value: token})
}

func (s *DataStore) GetAccessToken(ctx context.Context) (string, error) {
	return s.query.GetConfigValue(ctx, accessTokenKey)
}

func (s *DataStore) SetRefreshToken(ctx context.Context, token string) error {
	return s.query.SetConfigValue(ctx, db.SetConfigValueParams{Key: refreshTokenKey, Value: token})
}

func (s *DataStore) GetRefreshToken(ctx context.Context) (string, error) {
	return s.query.GetConfigValue(ctx, refreshTokenKey)
}

func (s *DataStore) SetTokenExpiry(ctx context.Context, expiry time.Time) error {
	return s.query.SetConfigValue(ctx, db.SetConfigValueParams{Key: tokenExpiry, Value: expiry.Format(time.RFC3339)})
}

func (s *DataStore) GetTokenExpiry(ctx context.Context) (time.Time, error) {
	strExpiry, err := s.query.GetConfigValue(ctx, tokenExpiry)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "could not get token expiry from store")
	}
	return time.Parse(time.RFC3339, strExpiry)
}

func (s *DataStore) DeleteTokens(ctx context.Context) error {
	err := s.query.DeleteConfigValue(ctx, tokenExpiry)
	if err != nil {
		return errors.Wrap(err, "could not delete token expiry from store")
	}
	err = s.query.DeleteConfigValue(ctx, refreshTokenKey)
	if err != nil {
		return errors.Wrap(err, "could not delete refresh token from store")
	}
	err = s.query.DeleteConfigValue(ctx, accessTokenKey)
	if err != nil {
		return errors.Wrap(err, "could not delete access token from store")
	}
	return nil
}
