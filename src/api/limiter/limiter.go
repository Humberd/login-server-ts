package limiter

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opentibiabr/login-server/src/configs"
	"github.com/opentibiabr/login-server/src/logger"

	"golang.org/x/time/rate"
)

type IPRateLimiter struct {
	Visitors map[string]*Visitor
	Mu       *sync.RWMutex
	Configs  configs.RateLimiter
	rejected atomic.Int64
}

type Visitor struct {
	Limiter  *rate.Limiter
	LastSeen time.Time
}

func (rl *IPRateLimiter) Init() {
	rl.Configs = configs.GetRateLimiterConfigs()
	go rl.cleanupVisitors()
}

func (rl *IPRateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.Mu.Lock()
	defer rl.Mu.Unlock()

	v, exists := rl.Visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.Configs.Rate, rl.Configs.Burst)
		rl.Visitors[ip] = &Visitor{limiter, time.Now()}
		return limiter
	}

	v.LastSeen = time.Now()
	return v.Limiter
}

func (rl *IPRateLimiter) cleanupVisitors() {
	for {
		time.Sleep(time.Minute)

		if n := rl.rejected.Swap(0); n > 0 {
			logger.Warn(fmt.Sprintf("rate limiter rejected %d requests in the last minute", n))
		}

		rl.Mu.Lock()
		for ip, v := range rl.Visitors {
			if time.Since(v.LastSeen) > 3*time.Minute {
				delete(rl.Visitors, ip)
			}
		}
		rl.Mu.Unlock()
	}
}

func (rl *IPRateLimiter) Limit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		limiter := rl.getVisitor(ip)
		if !limiter.Allow() {
			rl.rejected.Add(1)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
			return
		}
		c.Next()
	}
}
