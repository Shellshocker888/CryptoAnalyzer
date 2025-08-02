package logger

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Log *zap.Logger

func InitLogger() error {
	config := zap.NewProductionConfig()
	config.OutputPaths = []string{
		"logs/service.log",
		"stderr",
	}
	config.ErrorOutputPaths = []string{
		"logs/error.log",
		"stderr",
	}
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var err error
	Log, err = config.Build()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	return nil
}

func SyncLogger() {
	_ = Log.Sync()
}

func InitTestLogger() error {
	config := zap.NewDevelopmentConfig()
	config.OutputPaths = []string{"stdout"}
	config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)

	logger, err := config.Build()
	if err != nil {
		return fmt.Errorf("failed to initialize test logger: %w", err)
	}

	Log = logger

	return nil
}
