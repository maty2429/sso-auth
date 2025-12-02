package handler

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// NewRouter define todas las rutas y retorna el motor de Gin listo para usar
func NewRouter(authHandler *AuthHandler) *gin.Engine {
	r := gin.Default()

	// Configuración CORS (Vital para que el Frontend no falle)
	r.Use(cors.Default())

	// Grupo de rutas para la API v1 (Buenas prácticas de versionado)
	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
			auth.POST("/register", authHandler.Register)
			// Aquí añadirías el refresh: auth.POST("/refresh", authHandler.RefreshToken)
		}

		// Futuras rutas protegidas (ejemplo)
		// projects := v1.Group("/projects")
		// projects.Use(MiddlewareDeAutenticacion)
	}

	return r
}
