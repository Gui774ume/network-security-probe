/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
