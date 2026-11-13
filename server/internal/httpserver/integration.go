package httpserver

import (
	"authgo/internal/apidocs"
	"authgo/internal/auth"

	"github.com/gin-gonic/gin"
)

func registerIntegration(r *gin.Engine, identity *auth.Service) {
	apidocs.RegisterDocuments(r, identity)
}
