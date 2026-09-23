package api

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/opentibiabr/login-server/src/api/limiter"
	"github.com/opentibiabr/login-server/src/configs"
	"github.com/opentibiabr/login-server/src/database"
	"github.com/opentibiabr/login-server/src/logger"
	"github.com/opentibiabr/login-server/src/server"
	"google.golang.org/grpc"
)

type Api struct {
	Router         *gin.Engine
	DB             *sql.DB
	GrpcConnection *grpc.ClientConn
	server.ServerInterface
	BoostedCreatureID uint32
	BoostedBossID     uint32
	ServerPath        string
	CorePath          string
	LuaConfigManager  *configs.LuaConfigManager
}

func Initialize(gConfigs configs.GlobalConfigs) *Api {
	var _api Api
	var err error

	_api.DB = database.PullConnection(gConfigs)

	ipLimiter := &limiter.IPRateLimiter{
		Visitors: make(map[string]*limiter.Visitor),
		Mu:       &sync.RWMutex{},
	}

	ipLimiter.Init()

	gin.SetMode(gin.ReleaseMode)

	_api.Router = gin.New()
	// gin trusts X-Forwarded-For from anyone by default, which lets a client pick its own rate-limit key.
	if err := _api.Router.SetTrustedProxies(trustedProxies()); err != nil {
		logger.Error(fmt.Errorf("invalid %s: %v", envTrustedProxiesKey, err))
		_ = _api.Router.SetTrustedProxies(nil)
	}
	_api.Router.Use(logger.LogRequest())
	_api.Router.Use(gin.Recovery())
	_api.Router.Use(ipLimiter.Limit())
	_api.ServerPath = strings.TrimSpace(configs.GetEnvStr("SERVER_PATH", ""))
	if _api.ServerPath != "" {
		configPath := filepath.Join(_api.ServerPath, "config.lua")
		if _, statErr := os.Stat(configPath); statErr != nil {
			distPath := filepath.Join(_api.ServerPath, "config.lua.dist")
			if _, distErr := os.Stat(distPath); distErr == nil {
				configPath = distPath
			}
		}

		_api.LuaConfigManager, err = configs.NewLuaConfigManager(configPath)
		if err != nil {
			logger.Error(fmt.Errorf("error to load Lua configurations: %v", err))
		}
	}

	if _api.ServerPath != "" {
		_api.CorePath = filepath.ToSlash(_api.ServerPath)

		coreDirectory := strings.TrimSpace(_api.LuaConfigManager.GetString("coreDirectory"))
		if coreDirectory != "" {
			_api.CorePath = filepath.ToSlash(filepath.Join(_api.ServerPath, coreDirectory))
		}
	}

	_api.initializeRoutes()

	/* Generate HTTP/GRPC reverse proxy */

	_api.GrpcConnection, err = grpc.Dial(gConfigs.LoginServerConfigs.Grpc.Format(), grpc.WithInsecure())
	if err != nil {
		logger.Error(errors.New("couldn't start GRPC reverse proxy server, check if the login server is running and the GRPC port is open"))
	}

	return &_api
}

func (_api *Api) Run(gConfigs configs.GlobalConfigs) error {
	srv := &http.Server{
		Addr:              gConfigs.LoginServerConfigs.Http.Format(),
		Handler:           _api.Router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	err := srv.ListenAndServe()

	/* Make sure we free the reverse proxy connection */
	if _api.GrpcConnection != nil {
		closeErr := _api.GrpcConnection.Close()
		if closeErr != nil {
			logger.Error(closeErr)
		}
	}

	return err
}

const envTrustedProxiesKey = "LOGIN_TRUSTED_PROXIES"
const maxLoginBodyBytes = 16 << 10

func trustedProxies() []string {
	var proxies []string
	for _, p := range strings.Split(configs.GetEnvStr(envTrustedProxiesKey, ""), ",") {
		if p = strings.TrimSpace(p); p != "" {
			proxies = append(proxies, p)
		}
	}
	return proxies
}

func limitBody(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		}
		c.Next()
	}
}

func (_api *Api) GetName() string {
	return "api"
}

func (_api *Api) initializeRoutes() {
	login := []gin.HandlerFunc{limitBody(maxLoginBodyBytes), _api.login}
	_api.Router.POST("/", login...)
	_api.Router.POST("/login", login...)
	_api.Router.POST("/login.php", login...)
	_api.Router.POST("/crash-report", _api.crashReport)
}
