package database

import (
	"database/sql"
	"time"

	"github.com/opentibiabr/login-server/src/configs"
	"github.com/opentibiabr/login-server/src/logger"
)

const DefaultDbConnMaxLifetime = 3 * time.Minute

func PullConnection(gConfigs configs.GlobalConfigs) *sql.DB {
	DB, err := sql.Open("mysql", gConfigs.DBConfigs.GetConnectionString())
	if err != nil {
		logger.Panic(err)
	}

	maxOpen := gConfigs.DBConfigs.MaxOpenConns
	// 0 would mean unlimited to database/sql.
	if maxOpen <= 0 {
		maxOpen = configs.DefaultDBMaxOpenConns
	}
	DB.SetMaxOpenConns(maxOpen)
	DB.SetMaxIdleConns(gConfigs.DBConfigs.MaxIdleConns)
	DB.SetConnMaxLifetime(DefaultDbConnMaxLifetime)

	return DB
}
