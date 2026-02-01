package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/urfave/cli/v3"
	"magnax.ca/VPNManager/pkg/pivpn"
)

func CmdDaemon(ctx context.Context, cmd *cli.Command) error {
	return errors.New("not implemented")
}

func CmdListClients(ctx context.Context, cmd *cli.Command) error {
	vpn, err := pivpn.LoadVpn()
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", "::: Clients Summary :::")
	fmt.Printf("%-20s %-49s %s\n", "Client", "Public key", "Creation date")
	for _, client := range vpn.Clients {
		fmt.Printf("%-20s %-49s %s\n", client.Name, client.Interface.PrivateKey.Public().String(), client.CreationDate.String())
	}

	fmt.Printf("%s\n", "::: Disabled clients :::")
	for _, client := range vpn.Clients {
		if !client.Disabled {
			continue
		}
		fmt.Printf("%s\n", client.Name)
	}

	return nil
}

func CmdDisable(ctx context.Context, cmd *cli.Command) error {
	vpn, err := pivpn.LoadVpn()
	if err != nil {
		return err
	}

	if len(vpn.Clients) == 0 {
		return fmt.Errorf("no clients found")
	}

	if cmd.Bool("display-disabled") {
		for _, client := range vpn.Clients {
			if !client.Disabled {
				continue
			}
			fmt.Printf("[disabled] %s\n", client.Name)
		}
		return nil
	}

	confirmed := cmd.Bool("yes")
	names := cmd.StringArgs("name")

	if len(names) == 0 {
		// we don't have clients, present a list
		listClientsIndexed(vpn.Clients)
		selection, err := promptf("Please enter the index/names of the clients to disable: ")
		if err != nil {
			return err
		}
		list := strings.Split(selection, ",")
		for _, item := range list {
			item = strings.TrimSpace(item)
			if len(item) == 0 {
				continue
			}
			if isNumeric(item) {
				idx, err := strconv.Atoi(item)
				if err != nil {
					return err
				}
				idx -= 1
				if idx < 0 || idx >= len(vpn.Clients) {
					return fmt.Errorf("given index %d is not valid", idx)
				}
				names = append(names, vpn.Clients[idx].Name)
			} else {
				names = append(names, item)
			}
		}
	}

	var hasErrs bool

	for _, name := range names {
		if !confirmed {
			l, e := promptf("Disable %s? [y/N]", name)
			l = strings.ToLower(strings.TrimSpace(l))
			if len(l) == 0 || l[0] != 'y' {
				continue
			}
			if err != nil {
				hasErrs = true
				slog.ErrorContext(ctx, "error when getting confirmation", "error", e)
			}
		}
		err = vpn.DisableClient(name)
		if err != nil {
			hasErrs = true
			slog.ErrorContext(ctx, "error occurred when disabling client", "client", name, "error", err)
		} else {
			fmt.Printf("[disabled] %s\n", name)
		}
	}

	if hasErrs {
		return errors.New("error(s) when disabling client(s)")
	}
	return nil
}

func CmdEnable(ctx context.Context, cmd *cli.Command) error {
	vpn, err := pivpn.LoadVpn()
	if err != nil {
		return err
	}

	if len(vpn.Clients) == 0 {
		return fmt.Errorf("no clients found")
	}

	if cmd.Bool("display-disabled") {
		for _, client := range vpn.Clients {
			if !client.Disabled {
				continue
			}
			fmt.Printf("[disabled] %s\n", client.Name)
		}
		return nil
	}

	confirmed := cmd.Bool("yes")
	names := cmd.StringArgs("name")

	if len(names) == 0 {
		// we don't have clients, present a list
		listClientsIndexed(vpn.Clients)
		selection, err := promptf("Please enter the index/names of the clients to enable: ")
		if err != nil {
			return err
		}
		list := strings.Split(selection, ",")
		for _, item := range list {
			item = strings.TrimSpace(item)
			if len(item) == 0 {
				continue
			}
			if isNumeric(item) {
				idx, err := strconv.Atoi(item)
				if err != nil {
					return err
				}
				idx -= 1
				if idx < 0 || idx >= len(vpn.Clients) {
					return fmt.Errorf("given index %d is not valid", idx)
				}
				names = append(names, vpn.Clients[idx].Name)
			} else {
				names = append(names, item)
			}
		}
	}

	var hasErrs bool

	for _, name := range names {
		if !confirmed {
			l, e := promptf("Enable %s? [y/N] ", name)
			l = strings.ToLower(strings.TrimSpace(l))
			if len(l) == 0 || l[0] != 'y' {
				continue
			}
			if err != nil {
				hasErrs = true
				slog.ErrorContext(ctx, "error when getting confirmation", "error", e)
			}
		}
		err = vpn.EnableClient(name)
		if err != nil {
			hasErrs = true
			slog.ErrorContext(ctx, "error occurred when enabling client", "client", name, "error", err)
		} else {
			fmt.Printf("[enabled] %s\n", name)
		}
	}

	if hasErrs {
		return errors.New("error(s) when enabling client(s)")
	}
	return nil
}

func CmdRemove(ctx context.Context, cmd *cli.Command) error {
	vpn, err := pivpn.LoadVpn()
	if err != nil {
		return err
	}

	if len(vpn.Clients) == 0 {
		return fmt.Errorf("no clients found")
	}

	confirmed := cmd.Bool("yes")
	names := cmd.StringArgs("name")

	if len(names) == 0 {
		// we don't have clients, present a list
		listClientsIndexed(vpn.Clients)
		selection, err := promptf("Please enter the index/names of the clients to remove: ")
		if err != nil {
			return err
		}
		list := strings.Split(selection, ",")
		for _, item := range list {
			item = strings.TrimSpace(item)
			if len(item) == 0 {
				continue
			}
			if isNumeric(item) {
				idx, err := strconv.Atoi(item)
				if err != nil {
					return err
				}
				idx -= 1
				if idx < 0 || idx >= len(vpn.Clients) {
					return fmt.Errorf("given index %d is not valid", idx)
				}
				names = append(names, vpn.Clients[idx].Name)
			} else {
				names = append(names, item)
			}
		}
	}

	var hasErrs bool

	for _, name := range names {
		if !confirmed {
			l, e := promptf("Remove %s? [y/N] ", name)
			l = strings.ToLower(strings.TrimSpace(l))
			if len(l) == 0 || l[0] != 'y' {
				continue
			}
			if err != nil {
				hasErrs = true
				slog.ErrorContext(ctx, "error when getting confirmation", "error", e)
			}
		}
		err = vpn.RemoveClient(name)
		if err != nil {
			hasErrs = true
			slog.ErrorContext(ctx, "error occurred when remove client", "client", name, "error", err)
		} else {
			fmt.Printf("[removed] %s\n", name)
		}
	}

	if hasErrs {
		return errors.New("error(s) when removing client(s)")
	}
	return nil
}

func CmdAdd(ctx context.Context, cmd *cli.Command) error {
	vpn, err := pivpn.LoadVpn()
	if err != nil {
		return err
	}

	name := cmd.StringArg("name")

	err = vpn.AddClient(name)
	if err != nil {
		return nil
	}

	fmt.Printf("client %s added\n", name)
	return nil
}

func CmdSync(ctx context.Context, cmd *cli.Command) error {
	vpn, err := pivpn.LoadVpn()
	if err != nil {
		return nil
	}

	if err := vpn.SyncClients(); err != nil {
		return err
	}
	if err := vpn.SyncTunnel(); err != nil {
		return err
	}
	if err := vpn.SyncPihole(); err != nil {
		return err
	}

	return nil
}

func main() {
	cmd := &cli.Command{
		Name:                  "manager",
		Usage:                 "Manage the pivpn wireguard server",
		EnableShellCompletion: true,
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "List the vpn clients",
				Action: CmdListClients,
			},
			{
				Name:    "disable",
				Aliases: []string{"off"},
				Usage:   "Disable a client without deleting the configuration",
				Action:  CmdDisable,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "display-disabled",
						Aliases: []string{"v"},
						Usage:   "Show disabled clients only",
					},
					&cli.BoolFlag{
						Name:    "yes",
						Aliases: []string{"y"},
						Usage:   "Disable client(s) without confirmation",
					},
				},
				Arguments: []cli.Argument{
					&cli.StringArgs{
						Name: "name",
						Min:  0,
						Max:  -1,
					},
				},
			},
			{
				Name:    "enable",
				Aliases: []string{"on"},
				Usage:   "Enable an existing client",
				Action:  CmdEnable,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "display-disabled",
						Aliases: []string{"v"},
						Usage:   "Show disabled clients only",
					},
					&cli.BoolFlag{
						Name:    "yes",
						Aliases: []string{"y"},
						Usage:   "Enable client(s) without confirmation",
					},
				},
				Arguments: []cli.Argument{
					&cli.StringArgs{
						Name: "name",
						Min:  0,
						Max:  -1,
					},
				},
			},
			{
				Name:   "remove",
				Usage:  "Permanently remove a client, deleting the keys an all traces of this client from the system",
				Action: CmdRemove,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "yes",
						Aliases: []string{"y"},
						Usage:   "Remove client(s) without confirmation",
					},
				},
				Arguments: []cli.Argument{
					&cli.StringArgs{
						Name: "name",
						Min:  0,
						Max:  -1,
					},
				},
			},
			{
				Name:    "add",
				Aliases: []string{"a", "make"},
				Usage:   "Add a new client",
				Action:  CmdAdd,
				Arguments: []cli.Argument{
					&cli.StringArg{
						Name: "name",
					},
				},
			},
			{
				Name:   "sync",
				Usage:  "Re-synchronise the tunnel and clients",
				Action: CmdSync,
			},
			{
				Name:   "daemon",
				Usage:  "Run the remote vpn management daemon",
				Action: CmdDaemon,
				Hidden: true,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		slog.Error(err.Error())
	}
}
