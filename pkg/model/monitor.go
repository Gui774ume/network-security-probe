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
package model

// MonitorName - Monitor Name
type MonitorName string

var (
	// DockerMonitor - Docker monitor
	DockerMonitor MonitorName = "Docker"
	// CgroupMonitor - Cgroup monitor
	CgroupMonitor MonitorName = "Cgroup"
	// ConnectionMonitor - Connection monitor
	ConnectionMonitor MonitorName = "Connection"
	// ProcessMonitor - Process monitor
	ProcessMonitor MonitorName = "Process"
	// NetDeviceMonitor - NetDevice monitor
	NetDeviceMonitor MonitorName = "NetDevice"
	// NetworkAlertMonitor - Network alert monitor
	NetworkAlertMonitor MonitorName = "NetworkAlert"
	// SecurityProfileInformerMonitor - SecurityProfile informer monitor
	SecurityProfileInformerMonitor MonitorName = "SecurityProfileInformerMonitor"
)

// Monitor - Defines the Monitor interface
type Monitor interface {
	Init(nsp NSPInterface) error
	Start() error
	Stop() error
	GetName() MonitorName
}
