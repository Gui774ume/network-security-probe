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
package monitor

import (
	"github.com/Gui774ume/network-security-probe/pkg/config"
	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/cgroup"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/connection"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/container/docker"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/netdevice"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/process"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/tcsched"
)

// RegisterMonitors - Register monitors
func RegisterMonitors(config *config.NSPConfig) []model.Monitor {
	return []model.Monitor{
		&netdevice.Monitor,
		&connection.Monitor,
		&cgroup.Monitor,
		&process.Monitor,
		&docker.DMonitor,
		&tcsched.Monitor,
	}
}
