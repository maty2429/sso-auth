package main

import (
	"log"

	"sso/config"
	"sso/internal/adapters/handler"
	"sso/internal/adapters/repository"
	"sso/internal/core/service"
	"sso/pkg/db"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// 1. Cargar Configuración
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// 2. Conectar a Base de Datos
	dbPool, err := db.Connect(cfg.DBSource)
	if err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}
	defer dbPool.Close()

	// 3. Inicializar Capas (Inyección de Dependencias)
	// Repositorio (SQLC + Adapters)
	postgresRepo := repository.NewPostgresRepo(dbPool)

	// Servicio (Lógica de Negocio)
	authService := service.NewAuthService(postgresRepo, postgresRepo, cfg.JWTSecret) // PostgresRepo implements both User and Token repositories

	// Handler (Gin)
	authHandler := handler.NewAuthHandler(authService)

	// 4. Configurar Router (Gin)
	r := gin.Default()

	// Configurar CORS
	r.Use(cors.Default())

	// Rutas Públicas
	r.POST("/login", authHandler.Login)
	r.POST("/register", authHandler.Register)

	// 5. Correr Servidor
	log.Printf("Server starting on %s", cfg.Port)
	if err := r.Run(cfg.Port); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
