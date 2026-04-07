package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	"magnax.ca/VPNManager/internal/version"
	"magnax.ca/VPNManager/pkg/orchestrator"
)

func loadConfig(configFilePath string) (*orchestrator.Config, error) {
	src, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	return orchestrator.ParseConfig(src)
}

func CmdDaemon(ctx context.Context, cmd *cli.Command) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer cancel()

	configFilePath := cmd.String("config")

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			return nil
		default:
			err := func() error {
				cfg, err := loadConfig(configFilePath)
				if err != nil {
					return err
				}

				srvCtx, interuptCancel := signal.NotifyContext(ctx, syscall.SIGHUP)
				defer interuptCancel()

				srv := orchestrator.NewServer(srvCtx, cfg)
				if srv == nil {
					return fmt.Errorf("could not create server")
				}
				return srv.ListenAndServe(srvCtx)
			}()
			if err != nil {
				return err
			}
			// We either received an Interrupt (SIGINT), Kill (SIGKILL), or SIGHUP.
			// If not SIGHUP, ctx.Done() will be closed so Err() will be non-nil.
			// If SIGHUP, ctx.Done() is not closed so Err() is nil and
			// we'll land back in this case which will restart the server :)
			if ctx.Err() == nil {
				log.Printf("received HUP, reloading config")
			}
		}
	}
}

func main() {
	cmd := &cli.Command{
		Name:                  "orchestrator",
		Usage:                 "Orchestrates multiple vpn managers",
		EnableShellCompletion: true,
		Version:               version.Version(),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "/etc/vpnmanager/orchestrator.cfg",
				Usage:   "Load configuration from `FILE`",
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "daemon",
				Usage:  "Run the orchestration daemon",
				Action: CmdDaemon,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		slog.Error(err.Error())
	}
}
