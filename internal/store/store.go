package store

import (
	"context"
	"database/sql"
	"github.com/harnash/netatmo-trmnl/internal/store/db"
	"github.com/pkg/errors"
	_ "modernc.org/sqlite"
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

func (s *DataStore) SetAccessToken(ctx context.Context, token string) error {
	return s.query.SetConfigValue(ctx, db.SetConfigValueParams{Key: accessTokenKey, Value: token})
}

func (s *DataStore) GetAccessToken(ctx context.Context) (string, error) {
	return s.query.GetConfigValue(ctx, accessTokenKey)
}
