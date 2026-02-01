package main

import (
	"bufio"
	"fmt"
	"os"
	"unicode"

	"magnax.ca/VPNManager/pkg/pivpn"
)

func listClientsIndexed(clients []pivpn.Client) {
	for i, client := range clients {
		i += 1
		if client.Disabled {
			fmt.Printf("%2d [disabled] %s\n", i, client.Name)
		} else {
			fmt.Printf("%2d %s\n", i, client.Name)
		}
	}
}
func promptf(prompt string, args ...any) (string, error) {
	_, err := fmt.Printf(prompt, args...)
	if err != nil {
		return "", err
	}
	reader := bufio.NewReader(os.Stdin)

	return reader.ReadString('\n')
}

func isNumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
