package config

import (
	"os"
	"strconv"
	"strings"
)

type AppConfig struct {
	AppDatabasePath    string
	BBAASBaseURL       string
	BBAASAPIToken      string
	WorkerConcurrency  int
	WorkerLogPath      string
	WorkerDatabasePath string
}

func Load() AppConfig {
	appDatabasePath := envOrDefault("APP_DATABASE_PATH", "./data/ba11y.db")
	workerDatabasePath := envOrDefault("SCAN_WORKER_DB_PATH", appDatabasePath)

	return AppConfig{
		AppDatabasePath:    appDatabasePath,
		BBAASBaseURL:       envOrDefault("BBAAS_BASE_URL", "http://127.0.0.1:8080"),
		BBAASAPIToken:      firstNonEmptyEnv("BBAAS_API_TOKEN", "BBAAS_API_KEY"),
		WorkerConcurrency:  intEnvOrDefault("SCAN_WORKER_CONCURRENCY", 3),
		WorkerLogPath:      envOrDefault("SCAN_WORKER_LOG_PATH", "./data/logs"),
		WorkerDatabasePath: workerDatabasePath,
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

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(os.Getenv(key))
		if value != "" {
			return value
		}
	}
	return ""
}
