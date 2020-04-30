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
