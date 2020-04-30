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
