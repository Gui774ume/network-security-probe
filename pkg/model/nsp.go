package model

import (
	"sync"
	"time"

	"github.com/Gui774ume/ebpf"
	"k8s.io/client-go/rest"

	"github.com/Gui774ume/network-security-probe/pkg/config"
)

// NSPInterface - Exported interface used by the probes
type NSPInterface interface {
	GetWaitGroup() *sync.WaitGroup
	GetConfig() *config.NSPConfig
	GetKubeConfig() *rest.Config
	GetCollection() *ebpf.Collection
	GetBootTime() time.Time
	DispatchEvent(event ProbeEvent)
	SetupDeviceMonitor(event *DeviceEvent) error
	StopDeviceMonitor(event *DeviceEvent) error
}
