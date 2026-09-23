package database

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/opentibiabr/login-server/src/password"
	"github.com/opentibiabr/login-server/src/serviceerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	godSHA1       = "21298df8a3277357ee55b01df9530b535cf08ec1"
	testArgon2id  = "$argon2id$v=19$m=19456,t=2,p=1$TTNWdy9DOVcwVk5ISTFOTg$YEpzDGgMg4xBoYHgC58SVkZP+svlUAq8+sp3yXoCFcY"
	selectAccount = "SELECT id, type, premdays, lastday, password FROM accounts WHERE email = ? OR name = ?"
	upgradeHash   = "UPDATE accounts SET password = ? WHERE id = ? AND password = ?"
)

type argon2idArg struct{}

func (argon2idArg) Match(v driver.Value) bool {
	s, ok := v.(string)
	return ok && strings.HasPrefix(s, "$argon2id$") && password.Verify("god", s) == password.Match
}

func accountRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "type", "premdays", "lastday", "password"})
}

func expectAccountQuery(mock sqlmock.Sqlmock, login string) *sqlmock.ExpectedQuery {
	return mock.ExpectQuery(regexp.QuoteMeta(selectAccount)).WithArgs(login, login)
}

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, mock.ExpectationsWereMet())
		db.Close()
	})
	return db, mock
}

func assertInvalidCredentials(t *testing.T, err error) {
	publicErr, ok := serviceerrors.FromError(err)
	require.True(t, ok)
	assert.Equal(t, serviceerrors.CodeInvalidCredentials, publicErr.Code)
}

func TestLoadAccount_Argon2idMatch(t *testing.T) {
	db, mock := newMockDB(t)
	expectAccountQuery(mock, "tester").WillReturnRows(accountRows().AddRow(7, 5, 3, 100, testArgon2id))

	acc, err := LoadAccount("tester", "test", db)

	require.NoError(t, err)
	assert.Equal(t, uint32(7), acc.ID)
	assert.Equal(t, uint32(5), acc.Type)
	assert.Equal(t, uint32(3), acc.PremDays)
	assert.Equal(t, uint32(100), acc.LastDay)
}

func TestLoadAccount_LegacySHA1UpgradesHash(t *testing.T) {
	db, mock := newMockDB(t)
	expectAccountQuery(mock, "@god").WillReturnRows(accountRows().AddRow(1, 6, 0, 0, godSHA1))
	mock.ExpectExec(regexp.QuoteMeta(upgradeHash)).
		WithArgs(argon2idArg{}, 1, godSHA1).
		WillReturnResult(sqlmock.NewResult(0, 1))

	acc, err := LoadAccount("@god", "god", db)

	require.NoError(t, err)
	assert.Equal(t, uint32(1), acc.ID)
}

func TestLoadAccount_LegacyUpgradeFailureStillLogsIn(t *testing.T) {
	db, mock := newMockDB(t)
	expectAccountQuery(mock, "@god").WillReturnRows(accountRows().AddRow(1, 6, 0, 0, godSHA1))
	mock.ExpectExec(regexp.QuoteMeta(upgradeHash)).
		WithArgs(argon2idArg{}, 1, godSHA1).
		WillReturnError(errors.New("read-only"))

	acc, err := LoadAccount("@god", "god", db)

	require.NoError(t, err)
	assert.Equal(t, uint32(1), acc.ID)
}

func TestLoadAccount_WrongPassword(t *testing.T) {
	for _, stored := range []string{testArgon2id, godSHA1, "garbage"} {
		db, mock := newMockDB(t)
		expectAccountQuery(mock, "tester").WillReturnRows(accountRows().AddRow(7, 1, 0, 0, stored))

		acc, err := LoadAccount("tester", "wrong", db)

		assert.Nil(t, acc)
		assertInvalidCredentials(t, err)
	}
}

func TestLoadAccount_UnknownAccount(t *testing.T) {
	db, mock := newMockDB(t)
	expectAccountQuery(mock, "nobody").WillReturnRows(accountRows())

	acc, err := LoadAccount("nobody", "test", db)

	assert.Nil(t, acc)
	assertInvalidCredentials(t, err)
}

func TestLoadAccount_EmailOfOneNameOfAnother(t *testing.T) {
	db, mock := newMockDB(t)
	expectAccountQuery(mock, "shared").WillReturnRows(accountRows().
		AddRow(7, 1, 0, 0, godSHA1).
		AddRow(8, 1, 0, 0, testArgon2id))

	acc, err := LoadAccount("shared", "test", db)

	require.NoError(t, err)
	assert.Equal(t, uint32(8), acc.ID)
}

func TestLoadAccount_QueryError(t *testing.T) {
	db, mock := newMockDB(t)
	expectAccountQuery(mock, "tester").WillReturnError(errors.New("connection refused"))

	_, err := LoadAccount("tester", "test", db)

	publicErr, ok := serviceerrors.FromError(err)
	require.True(t, ok)
	assert.Equal(t, serviceerrors.CodeDatabaseUnavailable, publicErr.Code)
}
