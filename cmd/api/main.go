package main

import (
	"log"

	"sso/config"
	"sso/internal/adapters/handler"
	"sso/internal/adapters/repository"
	"sso/internal/core/service"
	"sso/pkg/db"
)

func main() {
	// 1. Cargar Configuración
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// 2. Conectar a Base de Datos (Pool de conexiones)
	dbPool, err := db.Connect(cfg.DBSource)
	if err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}
	defer dbPool.Close()

	// 3. Inicializar Capas (Inyección de Dependencias)
	// CAPA DE DATOS: Repositorio (SQLC)
	// Nota: PostgresRepo implementa tanto UserRepository como TokenRepository
	repo := repository.NewPostgresRepo(dbPool)

	// CAPA DE LÓGICA: Servicio
	// Inyectamos el repo tres veces porque cumple las tres interfaces (User, Token, Project)
	// Nota: Necesitamos actualizar NewAuthService para aceptar ProjectRepository
	authService := service.NewAuthService(repo, repo, repo, cfg.JWTSecret)

	// CAPA DE TRANSPORTE: Handler
	authHandler := handler.NewAuthHandler(authService)

	// 4. Inicializar Router (Aquí es donde limpiamos el main)
	r := handler.NewRouter(authHandler)

	// 5. Correr Servidor
	log.Printf("🚀 Server starting on port %s", cfg.Port)
	if err := r.Run(cfg.Port); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
