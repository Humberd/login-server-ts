package limiter

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/opentibiabr/login-server/src/configs"
	"github.com/stretchr/testify/assert"
)

func TestLimitRejectsAndCountsOverBurst(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rl := &IPRateLimiter{
		Visitors: make(map[string]*Visitor),
		Mu:       &sync.RWMutex{},
		Configs:  configs.RateLimiter{Rate: 0, Burst: 1},
	}
	handled := 0
	router := gin.New()
	router.Use(rl.Limit())
	router.POST("/", func(c *gin.Context) {
		handled++
		c.Status(http.StatusNoContent)
	})

	var codes []int
	for range 3 {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
		codes = append(codes, w.Code)
	}

	assert.Equal(t, []int{http.StatusNoContent, http.StatusTooManyRequests, http.StatusTooManyRequests}, codes)
	assert.Equal(t, 1, handled)
	assert.Equal(t, int64(2), rl.rejected.Load())
}
