package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/opentibiabr/login-server/src/api/limiter"
	"github.com/opentibiabr/login-server/src/grpc/login_proto_messages"
	"github.com/opentibiabr/login-server/src/logger"
	"github.com/opentibiabr/login-server/src/password"
	"github.com/opentibiabr/login-server/src/serviceerrors"
)

type Account struct {
	ID        uint32 `json:"id"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Type      uint32 `json:"type"`
	PremDays  uint32 `json:"premdays"`
	LastDay   uint32 `json:"lastday"`
	LastLogin uint32
}

const accountTypeGameMaster = 4
const secondsInADay = 24 * 60 * 60
const sessionDuration = 24 * time.Hour
const sessionPersistenceTimeout = 3 * time.Second
const maxLoginFailures = 10
const loginFailureWindow = 15 * time.Minute

var loginFailures = limiter.NewFailureLimiter(maxLoginFailures, loginFailureWindow)

var ErrAccountSessionStorageUnavailable = errors.New("account session persistence unavailable")

func (acc *Account) Authenticate(ctx context.Context, db *sql.DB, ip string) error {
	if db == nil {
		return serviceerrors.LoginService(
			serviceerrors.CodeDatabaseUnavailable,
			"DATABASE_UNAVAILABLE",
			errors.New("database connection is nil"),
		)
	}

	rows, err := db.QueryContext(ctx, "SELECT id, type, premdays, lastday, password FROM accounts WHERE email = ? OR name = ?", acc.Email, acc.Email)
	if err != nil {
		return err
	}
	var candidates []accountRow
	for rows.Next() {
		var row accountRow
		if err := rows.Scan(&row.id, &row.accountType, &row.premDays, &row.lastDay, &row.hash); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}

	ip = failureSource(ip)
	failureKeys := loginFailureKeys(acc.Email, ip, candidates)
	for _, key := range failureKeys {
		if loginFailures.Blocked(key) {
			return serviceerrors.TooManyLoginAttempts(loginFailureWindow)
		}
	}

	release, err := password.Acquire(ctx)
	if err != nil {
		return serviceerrors.LoginServiceBusy()
	}
	defer release()

	if len(candidates) == 0 {
		password.Burn(acc.Password)
		loginFailures.Fail(failureKeys...)
		return sql.ErrNoRows
	}

	for _, row := range candidates {
		switch password.Verify(acc.Password, row.hash) {
		case password.Match:
		case password.MatchLegacy:
			upgradePasswordHash(db, row.id, row.hash, acc.Password)
		default:
			continue
		}
		loginFailures.Reset(accountFailureKey(row.id, ip))
		acc.ID, acc.Type, acc.PremDays, acc.LastDay = row.id, row.accountType, row.premDays, row.lastDay
		return nil
	}

	loginFailures.Fail(failureKeys...)
	return sql.ErrNoRows
}

// Keyed per source so a stranger's failures lock only the stranger, never the owner.
// The accounts collation ignores case and accents, so every spelling that reaches an account shares its id's bucket.
func loginFailureKeys(login, ip string, candidates []accountRow) []string {
	if len(candidates) == 0 {
		sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(login))))
		return []string{"login:" + string(sum[:]) + "|" + ip}
	}
	keys := make([]string, len(candidates))
	for i, row := range candidates {
		keys[i] = accountFailureKey(row.id, ip)
	}
	return keys
}

func accountFailureKey(id uint32, ip string) string {
	return "account:" + strconv.FormatUint(uint64(id), 10) + "|" + ip
}

// One IPv6 host usually holds a whole /64, so a per-address key would let it rotate past the limit.
func failureSource(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return parsed.Mask(net.CIDRMask(64, 128)).String()
	}
	return ip
}

type accountRow struct {
	id, accountType, premDays, lastDay uint32
	hash                               string
}

func upgradePasswordHash(db *sql.DB, id uint32, legacyHash, plain string) {
	hash, err := password.Hash(plain)
	if err != nil {
		logger.Warn(fmt.Sprintf("account %d: argon2id password upgrade failed: %v", id, err))
		return
	}
	if _, err := db.Exec("UPDATE accounts SET password = ? WHERE id = ? AND password = ?", hash, id, legacyHash); err != nil {
		logger.Warn(fmt.Sprintf("account %d: argon2id password upgrade failed: %v", id, err))
	}
}

func (acc *Account) GetGrpcSession(sessionKey string) *login_proto_messages.Session {
	return &login_proto_messages.Session{
		IsPremium:    acc.PremDays > 0,
		PremiumUntil: acc.GetPremiumTime(),
		SessionKey:   sessionKey,
		LastLogin:    acc.LastLogin,
	}
}

func (acc *Account) IsAdmin() bool {
	return acc != nil && acc.Type >= accountTypeGameMaster
}

func (acc *Account) CreateSession(ctx context.Context, db *sql.DB) (string, error) {
	if acc == nil {
		return "", serviceerrors.LoginService(
			serviceerrors.CodeSessionCreateFailed,
			"SESSION_CREATE_FAILED",
			errors.New("account is nil"),
		)
	}
	if db == nil {
		return "", serviceerrors.LoginService(
			serviceerrors.CodeDatabaseUnavailable,
			"DATABASE_UNAVAILABLE",
			errors.New("database connection is nil"),
		)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", serviceerrors.LoginService(
			serviceerrors.CodeSessionCreateFailed,
			"SESSION_CREATE_FAILED",
			err,
		)
	}

	sessionKey := hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(sessionKey))
	expires := time.Now().Add(sessionDuration).Unix()

	if ctx == nil {
		ctx = context.Background()
	}

	writeCtx, cancel := context.WithTimeout(ctx, sessionPersistenceTimeout)
	defer cancel()

	if _, err := db.ExecContext(
		writeCtx,
		"INSERT INTO `account_sessions` (`id`, `account_id`, `expires`) VALUES (?, ?, ?)",
		fmt.Sprintf("%x", hash),
		acc.ID,
		expires,
	); err != nil {
		if isMissingAccountSessionsTable(err) {
			return "", serviceerrors.LoginService(
				serviceerrors.CodeSessionStorageUnavailable,
				"SESSION_STORAGE_UNAVAILABLE",
				fmt.Errorf("%w: %v", ErrAccountSessionStorageUnavailable, err),
			)
		}
		return "", serviceerrors.LoginService(
			serviceerrors.CodeSessionCreateFailed,
			"SESSION_CREATE_FAILED",
			err,
		)
	}

	return sessionKey, nil
}

func (acc *Account) GetPremiumTime() uint64 {
	if acc.PremDays > 0 {
		return uint64(time.Now().Unix()) + uint64(acc.PremDays*secondsInADay)
	}
	return 0
}

func LoadAccount(ctx context.Context, email string, password string, ip string, DB *sql.DB) (*Account, error) {
	acc := Account{Email: email, Password: password}
	if err := acc.Authenticate(ctx, DB, ip); err != nil {
		return nil, classifyAuthenticationError(err)
	}

	return &acc, nil
}

func classifyAuthenticationError(err error) error {
	if _, ok := serviceerrors.FromError(err); ok {
		return err
	}

	if errors.Is(err, sql.ErrNoRows) {
		return serviceerrors.InvalidCredentials()
	}

	if isDatabaseUnavailableError(err) {
		return serviceerrors.LoginService(
			serviceerrors.CodeDatabaseUnavailable,
			"DATABASE_UNAVAILABLE",
			err,
		)
	}

	return serviceerrors.LoginService(
		serviceerrors.CodeAccountDataUnavailable,
		"ACCOUNT_DATA_UNAVAILABLE",
		err,
	)
}

func isMissingAccountSessionsTable(err error) bool {
	return isMissingTableError(err, "account_sessions")
}

func isMissingTableError(err error, tableName string) bool {
	var mysqlErr *mysqlDriver.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1146
	}

	lowered := strings.ToLower(err.Error())
	return strings.Contains(lowered, strings.ToLower(tableName)) && strings.Contains(lowered, "doesn't exist")
}

func isDatabaseUnavailableError(err error) bool {
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var mysqlErr *mysqlDriver.MySQLError
	if errors.As(err, &mysqlErr) {
		switch mysqlErr.Number {
		case 1045, 1049, 2002, 2003, 2006, 2013:
			return true
		}
	}

	lowered := strings.ToLower(err.Error())
	return strings.Contains(lowered, "connection refused") ||
		strings.Contains(lowered, "can't connect") ||
		strings.Contains(lowered, "no such host")
}
