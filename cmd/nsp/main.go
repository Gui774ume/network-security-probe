package main

import (
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/network-security-probe/pkg/config"
	"github.com/Gui774ume/network-security-probe/pkg/nsp"
)

var (
	mainLogger = logrus.WithField("package", "main")
)

func main() {
	// Parse CLI arguments and config file
	cfg, err := config.NewConfigFromCLI()
	if err != nil {
		mainLogger.Fatalf("unable to load configuration file: %s", err)
	}

	// Initializes and start the network security probe
	probe, err := nsp.NewWithConfig(cfg)
	if err != nil {
		mainLogger.Fatalf("couldn't create a network security probe instance: %s", err)
	}
	if err = probe.Start(); err != nil {
		mainLogger.Fatalf("couldn't start the network security probe: %s", err)
	}

	// Wait until interruption
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	mainLogger.Debug("interrupt signal caught! Stopping now ...")

	// Stop and cleanup the network security probe
	if err = probe.Stop(); err != nil {
		mainLogger.Fatalf("couldn't stop the network security probe: %s", err)
	}
	return
}
