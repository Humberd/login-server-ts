package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (_api *Api) health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	if _api.DB == nil || _api.DB.PingContext(ctx) != nil {
		c.String(http.StatusServiceUnavailable, "database unreachable")
		return
	}

	c.String(http.StatusOK, "ok")
}
