package database

import (
	"testing"

	"github.com/opentibiabr/login-server/src/configs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullConnectionCapsThePool(t *testing.T) {
	for _, tt := range []struct{ configured, want int }{
		{configured: 0, want: configs.DefaultDBMaxOpenConns},
		{configured: -1, want: configs.DefaultDBMaxOpenConns},
		{configured: 3, want: 3},
	} {
		dbConfigs := configs.GetDBConfigs()
		dbConfigs.MaxOpenConns = tt.configured
		db := PullConnection(configs.GlobalConfigs{DBConfigs: dbConfigs})

		assert.Equal(t, tt.want, db.Stats().MaxOpenConnections, "configured %d", tt.configured)
		require.NoError(t, db.Close())
	}
}
