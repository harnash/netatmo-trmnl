package store

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/harnash/netatmo-trmnl/internal/store/db"
	"testing"
)

func TestDataStore_GetAccessToken(t *testing.T) {
	type fields struct {
		query *db.Queries
	}
	type args struct {
		ctx context.Context
	}

	sqlDb, mock, err := sqlmock.New()
	if err != nil {
		t.Error(err)
	}
	rows := sqlmock.NewRows([]string{"value"}).AddRow("good-token")
	mock.ExpectQuery(`^--.+\sSELECT value FROM config WHERE key = ?`).WillReturnRows(rows)
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name:   "returns valid token",
			fields: fields{query: db.New(sqlDb)},
			args:   args{ctx: context.TODO()},
			want:   "good-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &DataStore{
				query: tt.fields.query,
			}
			got, err := s.GetAccessToken(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAccessToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetAccessToken() got = %v, want %v", got, tt.want)
			}
		})
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDataStore_SetAccessToken(t *testing.T) {
	type fields struct {
		query *db.Queries
	}
	type args struct {
		ctx   context.Context
		token string
	}
	sqlDb, mock, err := sqlmock.New()
	if err != nil {
		t.Error(err)
	}
	mock.ExpectExec(`^--.+\sINSERT INTO config \(key, value\) VALUES \(\?, \?\) ON CONFLICT\(key\) DO UPDATE SET value=excluded.value`).WithArgs("access_token", "new-token").WillReturnResult(sqlmock.NewResult(1, 1))
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:    "save new token",
			fields:  fields{query: db.New(sqlDb)},
			args:    args{ctx: context.TODO(), token: "new-token"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &DataStore{
				query: tt.fields.query,
			}
			if err := s.SetAccessToken(tt.args.ctx, tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("SetAccessToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
