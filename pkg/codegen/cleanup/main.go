package main

import (
	"os"

	"github.com/sirupsen/logrus"
)

func main() {
	if err := os.RemoveAll("./pkg/generated"); err != nil {
		logrus.Fatal(err)
	}
	// if we don't have the docs file no need to clean it up
	if err := os.Remove("./docs.md"); err != nil && !os.IsNotExist(err) {
		logrus.Fatal(err)
	}
}
