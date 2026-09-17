package main

import (
	"os"

	"github.com/jay0lee/go-sa-key-manager/cmd"
)

var exitFunc = os.Exit

func run() int {
	rootCmd := cmd.NewRootCommand(nil)
	if err := rootCmd.Execute(); err != nil {
		return 1
	}
	return 0
}

func main() {
	exitFunc(run())
}
