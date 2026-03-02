package config

import (
	"os"
	"strconv"
	"strings"
)

type AppConfig struct {
	BBAASBaseURL       string
	BBAASAPIToken      string
	WorkerConcurrency  int
	WorkerLogPath      string
	WorkerDatabasePath string
}

func Load() AppConfig {
	return AppConfig{
		BBAASBaseURL:       envOrDefault("BBAAS_BASE_URL", "http://127.0.0.1:8080"),
		BBAASAPIToken:      strings.TrimSpace(os.Getenv("BBAAS_API_TOKEN")),
		WorkerConcurrency:  intEnvOrDefault("SCAN_WORKER_CONCURRENCY", 3),
		WorkerLogPath:      envOrDefault("SCAN_WORKER_LOG_PATH", "./data/logs"),
		WorkerDatabasePath: envOrDefault("SCAN_WORKER_DB_PATH", "./data/tasks.db"),
	}
}

func envOrDefault(key string, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}

	return value
}

func intEnvOrDefault(key string, defaultValue int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}

	return parsed
}
