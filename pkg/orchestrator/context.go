package orchestrator

import (
	"context"
	"log/slog"
)

type CtxKey struct {
	name string
}

var (
	loggerCtxKey = &CtxKey{"logger"}
)

func LoggerFromCtx(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerCtxKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

func CtxWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerCtxKey, logger)
}
