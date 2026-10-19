package database

import (
	"database/sql"
	"time"

	"github.com/opentibiabr/login-server/src/configs"
	"github.com/opentibiabr/login-server/src/logger"
)

// MariaDB's default max_connections (151) is shared with canary and MyAAC.
const DefaultMaxDbOpenConns = 10
const DefaultMaxDbIdleConns = 5
const DefaultDbConnMaxLifetime = 3 * time.Minute

func PullConnection(gConfigs configs.GlobalConfigs) *sql.DB {
	DB, err := sql.Open("mysql", gConfigs.DBConfigs.GetConnectionString())
	if err != nil {
		logger.Panic(err)
	}

	DB.SetMaxOpenConns(DefaultMaxDbOpenConns)
	DB.SetMaxIdleConns(DefaultMaxDbIdleConns)
	DB.SetConnMaxLifetime(DefaultDbConnMaxLifetime)

	return DB
}
