# VPNManager

A lightweight command-line tool written in Go for managing PiVPN installations using wireguard.
It provides a similar feature set to pivpn as a single fully-contained binary.
It is fully forward and backwards compatible with pivpn and can be used simultaneously.

 * Manage PiVPN clients (list, add, remove, enable, disable) directly via CLI commands
 * Sync configuration (in case it got out of sync)

## Future features

 * Fleet management:  
   If you have multiple PiVPN servers, manage them all from one interface

## Requirements

* Go 1.25+
* A working PiVPN installation with Wireguard
* User with sudo privileges or root

## Installation

`go get` the binary:

```bash
go get -u magnax.ca/VPNManager
```

In the future, we'll provide pre-built binaries.

## License

This project is licensed under the MIT License.