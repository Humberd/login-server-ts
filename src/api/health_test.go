package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

func healthStatus(t *testing.T, api *Api) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", api.health)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	return recorder.Code
}

func TestHealthReportsDatabase(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectPing()
	if code := healthStatus(t, &Api{DB: db}); code != http.StatusOK {
		t.Fatalf("reachable database: got %d", code)
	}

	mock.ExpectPing().WillReturnError(sqlmock.ErrCancelled)
	if code := healthStatus(t, &Api{DB: db}); code != http.StatusServiceUnavailable {
		t.Fatalf("unreachable database: got %d", code)
	}

	if code := healthStatus(t, &Api{}); code != http.StatusServiceUnavailable {
		t.Fatalf("no database: got %d", code)
	}
}
