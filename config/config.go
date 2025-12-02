package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DBSource  string
	Port      string
	JWTSecret string
}

func Load() (*Config, error) {
	// Cargar .env si existe (no obligatorio en producción si se usan vars de entorno reales)
	_ = godotenv.Load()

	cfg := &Config{
		DBSource:  os.Getenv("DB_URL"),
		Port:      os.Getenv("PORT"),
		JWTSecret: os.Getenv("JWT_SECRET"),
	}

	if cfg.Port == "" {
		cfg.Port = ":8080"
	}

	return cfg, nil
}
