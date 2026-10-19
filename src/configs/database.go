package configs

import (
	"fmt"
)

const EnvDBHostKey = "MYSQL_HOST"
const EnvDBNameKey = "MYSQL_DBNAME"
const EnvDBPassKey = "MYSQL_PASS"
const EnvDBPortKey = "MYSQL_PORT"
const EnvDBUserKey = "MYSQL_USER"
const EnvDBMaxOpenConnsKey = "MYSQL_MAX_OPEN_CONNS"
const EnvDBMaxIdleConnsKey = "MYSQL_MAX_IDLE_CONNS"

// MariaDB's default max_connections (151) is shared with canary and MyAAC.
const DefaultDBMaxOpenConns = 10
const DefaultDBMaxIdleConns = 5

type DBConfigs struct {
	Host         string
	Port         int
	Name         string
	User         string
	Pass         string
	MaxOpenConns int
	MaxIdleConns int
	Config
}

func (dbConfigs *DBConfigs) GetConnectionString() string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?parseTime=true",
		dbConfigs.User,
		dbConfigs.Pass,
		dbConfigs.Host,
		dbConfigs.Port,
		dbConfigs.Name,
	)
}

func (dbConfigs *DBConfigs) format() string {
	return fmt.Sprintf(
		"Database: %s:%d/%s",
		dbConfigs.Host,
		dbConfigs.Port,
		dbConfigs.Name,
	)
}
func GetDBConfigs() DBConfigs {
	return DBConfigs{
		Host:         GetEnvStr(EnvDBHostKey, "127.0.0.1"),
		Port:         GetEnvInt(EnvDBPortKey, 3306),
		Name:         GetEnvStr(EnvDBNameKey, "canary"),
		User:         GetEnvStr(EnvDBUserKey, "canary"),
		Pass:         GetEnvStr(EnvDBPassKey, "canary"),
		MaxOpenConns: GetEnvInt(EnvDBMaxOpenConnsKey, DefaultDBMaxOpenConns),
		MaxIdleConns: GetEnvInt(EnvDBMaxIdleConnsKey, DefaultDBMaxIdleConns),
	}
}
