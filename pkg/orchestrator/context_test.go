package orchestrator

import (
	"context"
	"log/slog"
	"reflect"
	"testing"
)

func TestCtxWithLogger(t *testing.T) {
	type args struct {
		ctx    context.Context
		logger *slog.Logger
	}
	newSlog := slog.New(slog.DiscardHandler)
	tests := []struct {
		name string
		args args
		want *slog.Logger
	}{
		{
			"ctx with no logger getting default",
			args{
				context.Background(),
				slog.Default(),
			},
			slog.Default(),
		},
		{
			"ctx with no logger getting custom",
			args{
				context.Background(),
				newSlog,
			},
			newSlog,
		},
		{
			"ctx with logger getting custom",
			args{
				context.WithValue(context.Background(), loggerCtxKey, slog.Default()),
				newSlog,
			},
			newSlog,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CtxWithLogger(tt.args.ctx, tt.args.logger)
			if logger, ok := got.Value(loggerCtxKey).(*slog.Logger); ok && !reflect.DeepEqual(logger, tt.want) {
				t.Errorf("CtxWithLogger().loggerCtxKey = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoggerFromCtx(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	newSlog := slog.New(slog.DiscardHandler)
	tests := []struct {
		name string
		args args
		want *slog.Logger
	}{
		{
			"empty ctx",
			args{
				context.Background(),
			},
			slog.Default(),
		},
		{
			"ctx with default",
			args{
				context.WithValue(context.Background(), loggerCtxKey, slog.Default()),
			},
			slog.Default(),
		},
		{
			"ctx with custom",
			args{
				context.WithValue(context.Background(), loggerCtxKey, newSlog),
			},
			newSlog,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LoggerFromCtx(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoggerFromCtx() = %v, want %v", got, tt.want)
			}
		})
	}
}
