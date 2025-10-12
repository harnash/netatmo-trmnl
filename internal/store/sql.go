package store

import (
	"context"
	"database/sql"
	"github.com/pkg/errors"
	_ "modernc.org/sqlite"
)

const defaultDSN = "netatmo-trmnl.sqlite3"
const schema = `
CREATE TABLE config (
    key VARCHAR(100),
    value VARCHAR(250)
)
`

type DataStore struct {
	db *sql.DB
}

func InitStore(dsn string) (*DataStore, error) {
	if dsn == "" {
		dsn = defaultDSN
	}
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errors.Wrap(err, "cannot open DB connection")
	}

	_, err = sqlDB.Exec("SELECT COUNT(*) FROM `config`")
	if err != nil {
		_, err = sqlDB.Exec(schema)
		if err != nil {
			return nil, errors.Wrap(err, "cannot initialize DB schema")
		}
	}

	return &DataStore{db: sqlDB}, nil
}

func (s *DataStore) getValue(ctx context.Context, key string) (string, error) {
	res, err := s.db.QueryContext(ctx, "SELECT `value` from `config` WHERE `key` = '?'", key)
	if err != nil {
		return "", errors.Wrap(err, "cannot fetch access token")
	}
	var val string
	err = res.Scan(&val)
	if err != nil {
		return "", errors.Wrap(err, "cannot fetch row data")
	}

	return val, nil
}

func (s *DataStore) setValue(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO `config` SET (`key` = '?',`value` = ?) ON DUPLICATE KEY UPDATE", key, value)
	return err
}

const accessTokenKey = "access_token"

func (s *DataStore) SetAccessToken(ctx context.Context, token string) error {
	return s.setValue(ctx, accessTokenKey, token)
}

func (s *DataStore) GetAccessToken(ctx context.Context) (string, error) {
	return s.getValue(ctx, accessTokenKey)
}
