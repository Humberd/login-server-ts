package limiter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFailureLimiterBlocksAfterLimit(t *testing.T) {
	l := NewFailureLimiter(3, time.Minute)

	for range 3 {
		assert.False(t, l.Blocked("a"))
		l.Fail("a")
	}

	assert.True(t, l.Blocked("a"))
	assert.False(t, l.Blocked("b"))

	l.Reset("a")
	assert.False(t, l.Blocked("a"))
}

func TestFailureLimiterCountsEveryKey(t *testing.T) {
	l := NewFailureLimiter(2, time.Minute)

	l.Fail("a", "b")
	l.Fail("b")

	assert.False(t, l.Blocked("a"))
	assert.True(t, l.Blocked("b"))
}

func TestFailureLimiterWindowExpires(t *testing.T) {
	l := NewFailureLimiter(1, 50*time.Millisecond)

	l.Fail("a")
	assert.True(t, l.Blocked("a"))

	time.Sleep(60 * time.Millisecond)
	assert.False(t, l.Blocked("a"))

	l.Fail("b")
	assert.Len(t, l.failures, 1, "expired keys are swept")
	assert.True(t, l.Blocked("b"))
}
