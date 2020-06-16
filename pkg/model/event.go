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

import (
	"fmt"
	"sync"
	"time"

	"docker.io/go-docker/api/types"
	"docker.io/go-docker/api/types/container"
	"docker.io/go-docker/api/types/strslice"
	"github.com/docker/go-connections/nat"
	"github.com/sirupsen/logrus"

	v1 "github.com/Gui774ume/network-security-probe/pkg/k8s/apis/securityprobe.datadoghq.com/v1"
	"github.com/Gui774ume/network-security-probe/pkg/model/kernel"
)

// EventType - Event type
type EventType string

var (
	// UnknownEventType - Dummy event to handle errors
	UnknownEventType EventType = "Unknown"
	// AnyEventType - Dummy event to handle selection of all events
	AnyEventType EventType = "Any"

	// ContainerCreatedEventType - Event type for a container creation event
	ContainerCreatedEventType EventType = "ContainerCreated"
	// ContainerRunningEventType - Event type for a running container event
	ContainerRunningEventType EventType = "ContainerRunning"
	// ContainerExitedEventType - Event type for a container exit event
	ContainerExitedEventType EventType = "ContainerExit"
	// ContainerDestroyedEventType - Event type for a container destroy event
	ContainerDestroyedEventType EventType = "ContainerDestroyed"
	// ContainerExecEventType - Event type for a container exec event
	ContainerExecEventType EventType = "ContainerExec"
	// ContainerAttachEventType - Event type for a container attach event
	ContainerAttachEventType EventType = "ContainerAttach"
	// ContainerConnectEventType - Event type for a container connect event
	ContainerConnectEventType EventType = "ContainerConnect"
	// ContainerDisconnectEventType - Event type for a container disconnect event
	ContainerDisconnectEventType EventType = "ContainerDisconnect"

	// FlowType - Flow event type
	FlowType EventType = "Flow"

	// NewNetDeviceType - New NetDevice event type
	NewNetDeviceType EventType = "NewNetDevice"
	// DeviceNetnsUpdateType - Device netns update event type
	DeviceNetnsUpdateType EventType = "DeviceNetnsUpdate"

	// SecurityProfileCreatedType - SecurityProfile created event type
	SecurityProfileCreatedType EventType = "SecurityProfileCreated"
	// SecurityProfileUpdatedType - SecurityProfile updated event type
	SecurityProfileUpdatedType EventType = "SecurityProfileUpdated"
	// SecurityProfileDeletedType - SecurityProfile deleted event type
	SecurityProfileDeletedType EventType = "SecurityProfileDeleted"

	// NetworkAlertType - Network alert type
	NetworkAlertType EventType = "NetworkAlert"
	// DNSQueryType - DNS Query type
	DNSQueryType EventType = "DNSQuery"
	// DNSResponseType - DNS response type
	DNSResponseType EventType = "DNSResponse"

	// ForkEventType - Fork event type
	ForkEventType EventType = "Fork"
	// ExecEventType - Exec event type
	ExecEventType EventType = "Exec"
	// ExitEventType - Exec event type
	ExitEventType EventType = "Exit"
)

// ProbeEvent - Generic event structure
type ProbeEvent interface {
	GetPid() uint32
	GetNetns() uint64
	GetLogEntry() *logrus.Entry
	GetMessage() string
	GetTimestamp() time.Time
	GetEventType() EventType
	GetEventMonitorName() MonitorName
	SetProcessCacheData(entry *ProcessCacheEntry)
	GetProcessCacheData() *ProcessCacheEntry
	SetNamespaceCacheData(entry *NamespaceCacheEntry)
	GetNamespaceCacheData() *NamespaceCacheEntry
}

const (
	// DeviceRegistration - Network device registration flag
	DeviceRegistration = iota
	// DeviceUnregistration - Network device unregistration flag
	DeviceUnregistration
	// DeviceFree - Network device structure free flag
	DeviceFree
)

// EventBase - Base struct for a probe event
type EventBase struct {
	ProcessData      *ProcessCacheEntry   `json:"process_data,omitempty"`
	NamespaceData    *NamespaceCacheEntry `json:"namespace_data,omitempty"`
	EventType        EventType            `json:"event_type"`
	EventMonitorName MonitorName          `json:"event_monitor_name"`
	Timestamp        time.Time            `json:"timestamp"`
	TTYName          string               `json:"tty_name"`
}

// GetTimestamp - Returns the event timestamp
func (eb *EventBase) GetTimestamp() time.Time {
	return eb.Timestamp
}

// GetEventType - Returns the event type
func (eb *EventBase) GetEventType() EventType {
	return eb.EventType
}

// GetEventMonitorName - Returns the event monitor name
func (eb *EventBase) GetEventMonitorName() MonitorName {
	return eb.EventMonitorName
}

// SetProcessCacheData - Sets the process cache data
func (eb *EventBase) SetProcessCacheData(pce *ProcessCacheEntry) {
	eb.ProcessData = pce
}

// GetProcessCacheData - Returns the process cache data
func (eb *EventBase) GetProcessCacheData() *ProcessCacheEntry {
	return eb.ProcessData
}

// SetNamespaceCacheData - Sets the namespace cache data
func (eb *EventBase) SetNamespaceCacheData(nce *NamespaceCacheEntry) {
	eb.NamespaceData = nce
}

// GetNamespaceCacheData - Returns the namespace cache data
func (eb *EventBase) GetNamespaceCacheData() *NamespaceCacheEntry {
	return eb.NamespaceData
}

// ProcessCacheEntry - Process cache entry
type ProcessCacheEntry struct {
	sync.RWMutex
	BinaryPath           string             `json:"binary_path"`
	Ppid                 uint32             `json:"ppid,omitempty"`
	Parent               *ProcessCacheEntry `json:"parent,omitempty"`
	Pid                  uint32             `json:"pid,omitempty"`
	TTYName              string             `json:"tty_name,omitempty"`
	ExecveTime           *time.Time         `json:"execve_time,omitempty"`
	ForkTime             *time.Time         `json:"fork_time,omitempty"`
	ForkThresholdReached bool               `json:"-"`
	ExitTime             *time.Time         `json:"exit_time,omitempty"`
}

// MultiprocessingThreshold - Multiprocessing threshold
var MultiprocessingThreshold = 100 * time.Millisecond

// IsExecveResolved - Checks if the execve & fork times are consistent to declare that
// the process and profile that are set in the current cacheEntry are the real process
// data. In other words this functions guesses if the process crossed the threshold to
// be considered as a multiprocessed or if we should wait to make sure that no another
// is on its way.
func (pce *ProcessCacheEntry) IsExecveResolved(timestamp time.Time, updateState bool) bool {
	if updateState {
		pce.Lock()
		defer pce.Unlock()
	} else {
		pce.RLock()
		defer pce.RUnlock()
	}
	if pce.ForkTime == nil || pce.ForkThresholdReached {
		return true
	}
	if pce.ExecveTime != nil && pce.ForkTime.Before(*pce.ExecveTime) {
		if updateState {
			pce.ForkThresholdReached = true
		}
		return true
	}
	if pce.ForkTime.Add(MultiprocessingThreshold).Before(timestamp) {
		if updateState {
			pce.ForkThresholdReached = true
		}
		return true
	}
	return false
}

// HasQuickExitTime - Checks if the exit time is below the fork threshold
func (pce *ProcessCacheEntry) HasQuickExitTime() bool {
	if pce.ExitTime == nil || pce.ForkTime == nil {
		return false
	}
	return pce.ForkTime.Add(MultiprocessingThreshold).After(*pce.ExitTime)
}

// IsInCache - Checks if the process is in cache
func (pce *ProcessCacheEntry) IsInCache() bool {
	pce.RLock()
	defer pce.RUnlock()
	inCache := pce.ExecveTime != nil || pce.ForkTime != nil
	return inCache
}

// NamespaceCacheEntry - Namespace cache entry
type NamespaceCacheEntry struct {
	sync.RWMutex
	Name      string     `json:"name"`
	ID        string     `json:"id"`
	Base      string     `json:"base"`
	Digest    string     `json:"digest"`
	Pod       string     `json:"pod"`
	Namespace string     `json:"namespace"`
	StartTime *time.Time `json:"start_time"`
	ExitTime  *time.Time `json:"-"`
}

// IsInCache - Checks if a namespace entry is in cache
func (nce *NamespaceCacheEntry) IsInCache() bool {
	nce.RLock()
	inCache := len(nce.Name) > 0
	nce.RUnlock()
	return inCache
}

// Metadata - Event metadata
type Metadata struct {
	Pidns        uint64   `json:"pidns"`
	Netns        uint64   `json:"netns"`
	TimestampRaw uint64   `json:"-"`
	TTYNameRaw   [64]byte `json:"-"`
	PID          uint32   `json:"pid"`
	TID          uint32   `json:"tid"`
}

func (m Metadata) getEntry() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"pidns": m.Pidns,
		"netns": m.Netns,
		"pid":   m.PID,
		"tid":   m.TID,
	})
}

func (m Metadata) String() string {
	return fmt.Sprintf("pidns:%v timestampRaw:%v ttyNameRaw:%v pid:%v tid:%v", m.Pidns, m.TimestampRaw, m.TTYNameRaw, m.PID, m.TID)
}

// Device - Device event data
type Device struct {
	DeviceFlag  int32    `json:"device_flag"`
	Ifindex     int32    `json:"ifindex"`
	Group       int32    `json:"group"`
	PeerIfindex int32    `json:"peer_ifindex"`
	Netns       uint64   `json:"netns"`
	NameRaw     [16]byte `json:"-"`
}

// DeviceEventRaw - Device event raw
type DeviceEventRaw struct {
	EventFlag uint64   `json:"event_flag"`
	Metadata  Metadata `json:"metadata"`
	Device    Device   `json:"device"`
	Peer      Device   `json:"peer"`
}

// DeviceEvent - Device event
type DeviceEvent struct {
	EventBase
	*DeviceEventRaw
	DeviceName string `json:"device_name"`
	PeerName   string `json:"peer_name"`
}

// GetPid - Returns the pid of the event
func (nde *DeviceEvent) GetPid() uint32 {
	return nde.DeviceEventRaw.Metadata.PID
}

// GetNetns - Returns the pidns of the event
func (nde *DeviceEvent) GetNetns() uint64 {
	return nde.DeviceEventRaw.Metadata.Netns
}

// GetLogEntry - Returns the event logrus fields
func (nde *DeviceEvent) GetLogEntry() *logrus.Entry {
	entry := nde.Metadata.getEntry()
	entry.WithFields(logrus.Fields{
		"tty": nde.TTYName,
	})
	if nde.Device.PeerIfindex == 0 {
		return entry.WithFields(logrus.Fields{
			"name":    nde.DeviceName,
			"netns":   nde.Device.Netns,
			"ifindex": nde.Device.Ifindex,
		})
	}
	return entry.WithFields(logrus.Fields{
		"device_name":    nde.DeviceName,
		"device_netns":   nde.Device.Netns,
		"device_ifindex": nde.Device.Ifindex,
		"peer_name":      nde.PeerName,
		"peer_netns":     nde.Peer.Netns,
		"peer_ifindex":   nde.Peer.Ifindex,
	})
}

// GetMessage - Returns a message for this event
func (nde *DeviceEvent) GetMessage() string {
	switch nde.EventFlag {
	case DeviceRegistration:
		if nde.Device.PeerIfindex == 0 {
			return "New network device registered"
		}
		return "New veth pair registered"
	case DeviceUnregistration:
		return "Device unregistered"
	case DeviceFree:
		return "Device structure freed"
	default:
		return fmt.Sprintf("Unknown event %v", nde.EventFlag)
	}
}

// DeviceNetnsUpdateRaw - Device Netns raw event
type DeviceNetnsUpdateRaw struct {
	Metadata Metadata `json:"metadata"`
	Device   Device   `json:"device"`
	NewNetns uint64   `json:"new_netns"`
}

// DeviceNetnsUpdate - Device Netns event
type DeviceNetnsUpdate struct {
	EventBase
	*DeviceNetnsUpdateRaw
	DeviceName string `json:"device_name"`
}

// GetPid - Returns the pid of the event
func (dnu *DeviceNetnsUpdate) GetPid() uint32 {
	return dnu.DeviceNetnsUpdateRaw.Metadata.PID
}

// GetNetns - Returns the pidns of the event
func (dnu *DeviceNetnsUpdate) GetNetns() uint64 {
	return dnu.DeviceNetnsUpdateRaw.Metadata.Netns
}

// GetLogEntry - Returns the event logrus fields
func (dnu *DeviceNetnsUpdate) GetLogEntry() *logrus.Entry {
	entry := dnu.Metadata.getEntry()
	entry.WithFields(logrus.Fields{
		"tty": dnu.TTYName,
	})
	return entry.WithFields(logrus.Fields{
		"name":      dnu.DeviceName,
		"old_netns": dnu.Device.Netns,
		"new_netns": dnu.NewNetns,
		"ifindex":   dnu.Device.Ifindex,
	})
}

// GetMessage - Returns a message for this event
func (dnu *DeviceNetnsUpdate) GetMessage() string {
	return "Network device netns update"
}

// FlowRaw - Network flow raw
type FlowRaw struct {
	Metadata Metadata  `json:"metadata"`
	AddrRaw  [2]uint64 `json:"-"`
	Port     uint16    `json:"port"`
	Family   uint16    `json:"family"`
}

// Flow - Network flow
type Flow struct {
	EventBase
	*FlowRaw
	Addr string `json:"addr"`
}

// GetPid - Returns the pid of the event
func (f *Flow) GetPid() uint32 {
	return f.FlowRaw.Metadata.PID
}

// GetNetns - Returns the pidns of the event
func (f *Flow) GetNetns() uint64 {
	return f.FlowRaw.Metadata.Netns
}

// GetLogEntry - Returns the event logrus fields
func (f *Flow) GetLogEntry() *logrus.Entry {
	entry := f.Metadata.getEntry()
	entry.WithFields(logrus.Fields{
		"tty": f.TTYName,
	})
	return entry.WithFields(logrus.Fields{
		"addr":   f.Addr,
		"port":   f.Port,
		"family": f.Family,
	})
}

// GetMessage - Returns a message for this event
func (f *Flow) GetMessage() string {
	return "Network flow registered"
}

// ContainerEvent - Container event
type ContainerEvent struct {
	EventBase
	InitPid             uint32                 `json:"init_pid"`
	Pidns               uint64                 `json:"pidns"`
	Cgroup              uint64                 `json:"cgroup"`
	Mntns               uint64                 `json:"mntns"`
	Netns               uint64                 `json:"netns"`
	Userns              uint64                 `json:"userns"`
	Image               string                 `json:"image"`
	K8sLabelImage       string                 `json:"k8s_label_image"`
	Tag                 string                 `json:"tag"`
	ContainerName       string                 `json:"container_name"`
	ContainerID         string                 `json:"container_id"`
	Digest              string                 `json:"digest"`
	Privileged          bool                   `json:"privileged"`
	CapAdd              strslice.StrSlice      `json:"cap_add"`
	AppArmorProfile     string                 `json:"apparmor_profile"`
	StartedAt           time.Time              `json:"started_at"`
	FinishedAt          time.Time              `json:"finished_at"`
	PortBindings        nat.PortMap            `json:"port_bindings"`
	SecurityOpt         []string               `json:"security_opt"`
	CommandPath         string                 `json:"command_path"`
	CommandArgs         []string               `json:"command_args"`
	OverlayFsMergedPath string                 `json:"overlayfs_merged_path"`
	Resources           container.Resources    `json:"resources"`
	NetworkSettings     *types.NetworkSettings `json:"network_settings"`
	MountPoints         []types.MountPoint     `json:"mount_points"`
	Labels              map[string]string      `json:"labels"`
}

// GetPid - Returns the pid of the event
func (ce ContainerEvent) GetPid() uint32 {
	return ce.InitPid
}

// GetNetns - Returns the pidns of the event
func (ce ContainerEvent) GetNetns() uint64 {
	return ce.Netns
}

// GetLogEntry - Returns the event logrus fields
func (ce ContainerEvent) GetLogEntry() *logrus.Entry {
	fields := logrus.Fields{}
	for label, value := range ce.Labels {
		fields[label] = value
	}
	return logrus.WithFields(logrus.Fields{
		"image":     ce.Image,
		"digest":    ce.Digest,
		"container": ce.ContainerName,
		"init_pid":  ce.InitPid,
	}).WithFields(fields)
}

// GetMessage - Returns a message for this event
func (ce ContainerEvent) GetMessage() string {
	return string(ce.EventType)
}

func (ce ContainerEvent) String() string {
	networksCount := 0
	if ce.NetworkSettings != nil {
		networksCount = len(ce.NetworkSettings.Networks)
	}
	return fmt.Sprintf(
		"%v Image:%v Name:%v ContainerID:%v InitPid:%v Digest:%v Privileged:%v CapAdd:%v CommandPath:%v CommandArgs:%v NetworksCount:%v Pidns:%v Cgroup:%v Mntns:%v Netns:%v Userns:%v AppArmorProfile:%v SecurityOpt:%v",
		ce.EventType,
		ce.Image,
		ce.ContainerName,
		ce.ContainerID,
		ce.InitPid,
		ce.Digest,
		ce.Privileged,
		ce.CapAdd,
		ce.CommandPath,
		ce.CommandArgs,
		networksCount,
		ce.Pidns,
		ce.Cgroup,
		ce.Mntns,
		ce.Netns,
		ce.Userns,
		ce.AppArmorProfile,
		ce.SecurityOpt,
	)
}

// SecurityProfileCreatedEvent - SecurityProfile Created event
type SecurityProfileCreatedEvent struct {
	EventBase
	Profile *v1.SecurityProfile
}

// GetPid - Returns the pid of the event
func (spc *SecurityProfileCreatedEvent) GetPid() uint32 {
	return 0
}

// GetNetns - Returns the pidns of the event
func (spc *SecurityProfileCreatedEvent) GetNetns() uint64 {
	return 0
}

// GetLogEntry - Returns the event logrus fields
func (spc SecurityProfileCreatedEvent) GetLogEntry() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"name":      spc.Profile.Name,
		"namespace": spc.Profile.Namespace,
		"cluster":   spc.Profile.ClusterName,
		"kind":      spc.Profile.Kind,
	})
}

// GetMessage - Returns a message for this event
func (spc SecurityProfileCreatedEvent) GetMessage() string {
	return "New SecurityProfile detected"
}

// SecurityProfileUpdatedEvent - SecurityProfile Created event
type SecurityProfileUpdatedEvent struct {
	EventBase
	Old *v1.SecurityProfile
	New *v1.SecurityProfile
}

// GetPid - Returns the pid of the event
func (spu *SecurityProfileUpdatedEvent) GetPid() uint32 {
	return 0
}

// GetNetns - Returns the pidns of the event
func (spu *SecurityProfileUpdatedEvent) GetNetns() uint64 {
	return 0
}

// GetLogEntry - Returns the event logrus fields
func (spu SecurityProfileUpdatedEvent) GetLogEntry() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"name":      spu.Old.Name,
		"namespace": spu.Old.Namespace,
		"cluster":   spu.Old.ClusterName,
		"kind":      spu.Old.Kind,
	})
}

// GetMessage - Returns a message for this event
func (spu SecurityProfileUpdatedEvent) GetMessage() string {
	return "SecurityProfile updated"
}

// SecurityProfileDeletedEvent - SecurityProfile Created event
type SecurityProfileDeletedEvent struct {
	EventBase
	Profile *v1.SecurityProfile
}

// GetPid - Returns the pid of the event
func (spd *SecurityProfileDeletedEvent) GetPid() uint32 {
	return 0
}

// GetNetns - Returns the pidns of the event
func (spd *SecurityProfileDeletedEvent) GetNetns() uint64 {
	return 0
}

// GetLogEntry - Returns the event logrus fields
func (spd SecurityProfileDeletedEvent) GetLogEntry() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"name":      spd.Profile.Name,
		"namespace": spd.Profile.Namespace,
		"cluster":   spd.Profile.ClusterName,
		"kind":      spd.Profile.Kind,
	})
}

// GetMessage - Returns a message for this event
func (spd SecurityProfileDeletedEvent) GetMessage() string {
	return "SecurityProfile Deleted"
}

// NetworkAlertRaw - Network alert raw
type NetworkAlertRaw struct {
	Netns         uint64                       `json:"netns"`
	TimestampRaw  uint64                       `json:"-"`
	Ifindex       uint32                       `json:"ifindex"`
	PID           uint32                       `json:"pid"`
	ProfileID     uint32                       `json:"-"`
	BinaryID      uint32                       `json:"-"`
	Action        kernel.SecurityProfileAction `json:"action"`
	DataPath      kernel.TrafficType           `json:"data_path"`
	Alert         kernel.NetworkAlert          `json:"alert,omitempty"`
	InterfaceType kernel.InterfaceType         `json:"interface_type"`
	NatHeadKey    uint32                       `json:"-"`
	// Ethernet (L2)
	NProtocol        kernel.NetworkProtocol `json:"network_protocol"`
	DestMACAddrRaw   [6]byte                `json:"-"`
	SourceMACAddrRaw [6]byte                `json:"-"`
	Padding1         [2]byte                `json:"-"`
	// IP (Network layer L3)
	IPVersion      uint8                    `json:"ip_version"`
	TProtocol      kernel.TransportProtocol `json:"transport_protocol"`
	TotLen         uint16                   `json:"tot_len"`
	PacketID       uint32                   `json:"packet_id"`
	FragmentOffset uint16                   `json:"fragment_offset"`
	Padding2       [6]byte                  `json:"-"`
	SourceIPRaw    [2]uint64                `json:"-"`
	DestIPRaw      [2]uint64                `json:"-"`
	// Transport (L4)
	Flags      uint64 `json:"flags"`
	SourcePort uint16 `json:"source_port"`
	DestPort   uint16 `json:"dest_port"`
	Padding3   uint32 `json:"-"`
	// Application (L7)
	AProtocol kernel.ApplicationProtocol `json:"application_protocol"`
	Padding4  uint16                     `json:"-"`
	Offset    uint32                     `json:"-"`
}

// NetworkAlertEvent - Network alert event
type NetworkAlertEvent struct {
	EventBase
	*NetworkAlertRaw
	DestMACAddr   string `json:"dest_mac_addr"`
	SourceMACAddr string `json:"source_mac_addr"`
	SourceIP      string `json:"source_ip"`
	DestIP        string `json:"dest_ip"`
}

// GetPid - Returns the pid of the event
func (nae *NetworkAlertEvent) GetPid() uint32 {
	return nae.NetworkAlertRaw.PID
}

// GetNetns - Returns the pidns of the event
func (nae *NetworkAlertEvent) GetNetns() uint64 {
	return nae.NetworkAlertRaw.Netns
}

// GetLogEntry - Returns the event logrus fields
func (nae *NetworkAlertEvent) GetLogEntry() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"ifindex": nae.Ifindex,
		"netns":   nae.Netns,
		"pid":     nae.PID,
		"action":  nae.Action,
		// "data_path":      nae.DataPath,
		"interface_type": nae.InterfaceType,
		"l3":             nae.NProtocol,
		"l4":             nae.TProtocol,
		"l7":             nae.AProtocol,
		"source_ip":      nae.SourceIP,
		"dest_ip":        nae.DestIP,
		"source_port":    nae.SourcePort,
		"dest_port":      nae.DestPort,
		"source_mac":     nae.SourceMACAddr,
		"dest_mac":       nae.DestMACAddr,
		"ip_version":     nae.IPVersion,
		// "tot_len":        nae.TotLen,
		// "packet_id":      nae.PacketID,
		// "frag_off":       nae.FragmentOffset,
	})
}

// GetMessage - Returns a message for this event
func (nae *NetworkAlertEvent) GetMessage() string {
	return fmt.Sprintf(
		"Suspicious %s traffic detected: %s violation(s) detected",
		nae.DataPath,
		nae.Alert,
	)
}

// DNSKey - DNS key structure from the kernel
type DNSKey struct {
	NameRaw     [kernel.DNSMaxLength]byte `json:"-"`
	Cookie      uint32                    `json:"-"`
	TrafficType uint8                     `json:"-"`
	Layer       uint8                     `json:"-"`
	Padding     uint16                    `json:"-"`
}

// DNSHeader - DNS header structure from the kernel
type DNSHeader struct {
	QueryID uint16 `json:"query_id"`
	Flags   uint16 `json:"flags"`
	QDCount uint16 `json:"qdcount"`
	ANCount uint16 `json:"ancount"`
	NSCount uint16 `json:"nscount"`
	ARCount uint16 `json:"arcount"`
}

// DNSQuerySpec - DNS query spec structure from the kernel
type DNSQuerySpec struct {
	DNSKey
	Qtype  kernel.DNSRecordType `json:"qtype"`
	QClass uint16               `json:"qclass"`
}

// DNSQueryRaw - DNS query structure from the kernel
type DNSQueryRaw struct {
	NetworkAlertRaw
	DNSHeader    DNSHeader    `json:"dns_header"`
	DNSQuerySpec DNSQuerySpec `json:"dns_query"`
}

// DNSQueryEvent - DNS query event
type DNSQueryEvent struct {
	EventBase
	*DNSQueryRaw
	DestMACAddr   string `json:"dest_mac_addr"`
	SourceMACAddr string `json:"source_mac_addr"`
	SourceIP      string `json:"source_ip"`
	DestIP        string `json:"dest_ip"`
	Domain        string `json:"domain"`
}

// GetPid - Returns the pid of the event
func (dqe *DNSQueryEvent) GetPid() uint32 {
	return dqe.DNSQueryRaw.NetworkAlertRaw.PID
}

// GetNetns - Returns the pidns of the event
func (dqe *DNSQueryEvent) GetNetns() uint64 {
	return dqe.DNSQueryRaw.NetworkAlertRaw.Netns
}

// GetLogEntry - Returns the event logrus fields
func (dqe *DNSQueryEvent) GetLogEntry() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"ifindex": dqe.Ifindex,
		"netns":   dqe.Netns,
		"pid":     dqe.PID,
		"action":  dqe.Action,
		// "data_path":      dqe.DataPath,
		"interface_type": dqe.InterfaceType,
		"l3":             dqe.NProtocol,
		"l4":             dqe.TProtocol,
		"l7":             dqe.AProtocol,
		"source_ip":      dqe.SourceIP,
		"dest_ip":        dqe.DestIP,
		"source_port":    dqe.SourcePort,
		"dest_port":      dqe.DestPort,
		"source_mac":     dqe.SourceMACAddr,
		"dest_mac":       dqe.DestMACAddr,
		"ip_version":     dqe.IPVersion,
		// "tot_len":        dqe.TotLen,
		// "packet_id":      dqe.PacketID,
		// "frag_off":       dqe.FragmentOffset,
		"domain": dqe.Domain,
	})
}

// GetMessage - Returns a message for this event
func (dqe *DNSQueryEvent) GetMessage() string {
	if dqe.Alert&kernel.DNSAlert == kernel.DNSAlert {
		return fmt.Sprintf(
			"Suspicious %s DNS traffic detected: %s",
			dqe.DataPath,
			dqe.Alert,
		)
	} else if dqe.Alert != 0 {
		return fmt.Sprintf(
			"Suspicious %s traffic detected: %s violation(s) detected",
			dqe.DataPath,
			dqe.Alert,
		)
	}
	return fmt.Sprintf(
		"%s DNS traffic",
		dqe.DataPath,
	)
}

// DNSResponseSpec - DNS response spec structure from the kernel
type DNSResponseSpec struct {
	DNSKey
	IPRaw    [2]uint64            `json:"-"`
	TTL      uint32               `json:"ttl"`
	Type     kernel.DNSRecordType `json:"type"`
	Class    uint16               `json:"class"`
	RDLength uint16               `json:"rdlength"`
	Padding  [6]byte              `json:"-"`
}

// DNSResponseRaw - DNS response structure from the kernel
type DNSResponseRaw struct {
	QueryTimestampRaw uint64 `json:"-"`
	NetworkAlertRaw
	DNSHeader       DNSHeader       `json:"dns_header"`
	Padding         uint32          `json:"-"`
	DNSResponseSpec DNSResponseSpec `json:"dns_response"`
}

// DNSResponseEvent - DNS query event
type DNSResponseEvent struct {
	EventBase
	*DNSResponseRaw
	DestMACAddr    string        `json:"dest_mac_addr"`
	SourceMACAddr  string        `json:"source_mac_addr"`
	SourceIP       string        `json:"source_ip"`
	DestIP         string        `json:"dest_ip"`
	Domain         string        `json:"domain"`
	ResolvedIP     string        `json:"resolved_ip"`
	QueryTimestamp time.Time     `json:"query_timestamp"`
	ResponseTime   time.Duration `json:"response_time"`
}

// GetPid - Returns the pid of the event
func (dre *DNSResponseEvent) GetPid() uint32 {
	return dre.DNSResponseRaw.NetworkAlertRaw.PID
}

// GetNetns - Returns the pidns of the event
func (dre *DNSResponseEvent) GetNetns() uint64 {
	return dre.DNSResponseRaw.NetworkAlertRaw.Netns
}

// GetLogEntry - Returns the event logrus fields
func (dre *DNSResponseEvent) GetLogEntry() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"ifindex": dre.Ifindex,
		"netns":   dre.Netns,
		"pid":     dre.PID,
		"action":  dre.Action,
		// "data_path":      dre.DataPath,
		"interface_type": dre.InterfaceType,
		"l3":             dre.NProtocol,
		"l4":             dre.TProtocol,
		"l7":             dre.AProtocol,
		"source_ip":      dre.SourceIP,
		"dest_ip":        dre.DestIP,
		"source_port":    dre.SourcePort,
		"dest_port":      dre.DestPort,
		"source_mac":     dre.SourceMACAddr,
		"dest_mac":       dre.DestMACAddr,
		"ip_version":     dre.IPVersion,
		// "tot_len":        dre.TotLen,
		// "packet_id":      dre.PacketID,
		// "frag_off":       dre.FragmentOffset,
		"domain":      dre.Domain,
		"resolved_ip": dre.ResolvedIP,
		// "query_timestamp": dre.QueryTimestamp,
		"response_time": dre.ResponseTime,
	})
}

// GetMessage - Returns a message for this event
func (dre *DNSResponseEvent) GetMessage() string {
	if dre.Alert&kernel.DNSAlert == kernel.DNSAlert {
		return fmt.Sprintf(
			"Suspicious %s DNS traffic detected: %s",
			dre.DataPath,
			dre.Alert,
		)
	} else if dre.Alert != 0 {
		return fmt.Sprintf(
			"Suspicious %s traffic detected: %s violation(s) detected",
			dre.DataPath,
			dre.Alert,
		)
	}
	return fmt.Sprintf(
		"%s DNS traffic",
		dre.DataPath,
	)
}

// ForkRaw - Fork raw
type ForkRaw struct {
	Metadata   Metadata `json:"metadata"`
	CloneFlags uint64   `json:"clone_flags"`
	StackStart uint64   `json:"stack_start"`
	StackSize  uint64   `json:"stack_size"`
	ChildPid   uint32   `json:"child_pid"`
}

// ForkEvent - Fork event
type ForkEvent struct {
	EventBase
	*ForkRaw
}

// IsNewProcess - Returns true if the clone call created a new process
func (fe *ForkEvent) IsNewProcess() bool {
	if fe.CloneFlags&uint64(kernel.SIGCHLD) == uint64(kernel.SIGCHLD) {
		return true
	}
	return false
}

// GetPid - Returns the pid of the event
func (fe *ForkEvent) GetPid() uint32 {
	return fe.ForkRaw.Metadata.PID
}

// GetNetns - Returns the pidns of the event
func (fe *ForkEvent) GetNetns() uint64 {
	return fe.ForkRaw.Metadata.Netns
}

// GetLogEntry - Returns the event logrus fields
func (fe *ForkEvent) GetLogEntry() *logrus.Entry {
	entry := fe.Metadata.getEntry()
	entry.WithFields(logrus.Fields{
		"tty": fe.TTYName,
	})
	return entry.WithFields(logrus.Fields{
		"child_pid": fe.ChildPid,
	})
}

// GetMessage - Returns a message for this event
func (fe *ForkEvent) GetMessage() string {
	return "Process fork detected"
}

// ProcessEventType - Process event type
type ProcessEventType uint32

const (
	// Execve - Execve process event type
	Execve ProcessEventType = iota
	// Exit - Exit process event type
	Exit
)

// ExecRaw - Exec raw
type ExecRaw struct {
	Metadata Metadata             `json:"metadata"`
	Type     ProcessEventType     `json:"-"`
	Cookie   uint32               `json:"-"`
	PathRaw  [kernel.PathMax]byte `json:"-"`
}

// ResolveEventType - Returns the event type
func (er *ExecRaw) ResolveEventType() EventType {
	switch er.Type {
	case Execve:
		return ExecEventType
	case Exit:
		return ExitEventType
	default:
		return UnknownEventType
	}
}

// ExecEvent - Exec event
type ExecEvent struct {
	EventBase
	*ExecRaw
	Path string `json:"path"`
}

// GetPid - Returns the pid of the event
func (ee *ExecEvent) GetPid() uint32 {
	return ee.ExecRaw.Metadata.PID
}

// GetNetns - Returns the pidns of the event
func (ee *ExecEvent) GetNetns() uint64 {
	return ee.ExecRaw.Metadata.Netns
}

// GetLogEntry - Returns the event logrus fields
func (ee *ExecEvent) GetLogEntry() *logrus.Entry {
	entry := ee.Metadata.getEntry()
	entry.WithFields(logrus.Fields{
		"tty": ee.TTYName,
	})
	return entry.WithFields(logrus.Fields{
		"path": ee.Path,
	})
}

// GetMessage - Returns a message for this event
func (ee *ExecEvent) GetMessage() string {
	return "New program started"
}
