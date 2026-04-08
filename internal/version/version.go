package version

import (
	"fmt"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func Version() string {
	return fmt.Sprintf("%s (%s) built on %s by %s", version, commit, date, builtBy)
}

func RawVersion() string {
	return version
}

func RawCommit() string {
	return commit
}
