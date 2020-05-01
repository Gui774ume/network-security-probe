package nsp

import (
	"bytes"
	"math/rand"
	"sync"
	"time"
	"unsafe"

	"github.com/DataDog/gopsutil/host"
	"github.com/Gui774ume/ebpf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Gui774ume/network-security-probe/pkg/config"
	"github.com/Gui774ume/network-security-probe/pkg/k8s/informer"
	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/model/kernel"
	"github.com/Gui774ume/network-security-probe/pkg/monitor"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/tcsched"
	"github.com/Gui774ume/network-security-probe/pkg/probe"
	"github.com/Gui774ume/network-security-probe/pkg/processor"
	"github.com/Gui774ume/network-security-probe/pkg/utils"
)

var (
	nspLogger = logrus.WithField("package", "nsp")
)

// NetworkSecurityProbe - Network Security probe
type NetworkSecurityProbe struct {
	KubeConfig   *rest.Config
	KubeInformer *informer.SecurityProfileInformer
	Config       *config.NSPConfig
	Collection   *ebpf.Collection
	Processors   map[model.EventType][]model.Processor
	Monitors     []model.Monitor
	TCMonitors   map[int32]model.Monitor
	wg           *sync.WaitGroup
	bootTime     time.Time
	hostNetns    uint64
	Cache        *Cache
}

// GetWaitGroup - Returns the wait group of the NSP
func (nsp *NetworkSecurityProbe) GetWaitGroup() *sync.WaitGroup {
	return nsp.wg
}

// GetConfig - Returns the config of the NSP
func (nsp *NetworkSecurityProbe) GetConfig() *config.NSPConfig {
	return nsp.Config
}

// GetKubeConfig - Returns the K8s config of the NSP
func (nsp *NetworkSecurityProbe) GetKubeConfig() *rest.Config {
	return nsp.KubeConfig
}

// GetCollection - Returns the eBPF collection of the NSP
func (nsp *NetworkSecurityProbe) GetCollection() *ebpf.Collection {
	return nsp.Collection
}

// GetBootTime - Returns the boot time of the host
func (nsp *NetworkSecurityProbe) GetBootTime() time.Time {
	return nsp.bootTime
}

// GetHostNetns - Returns the host netns
func (nsp *NetworkSecurityProbe) GetHostNetns() uint64 {
	return nsp.hostNetns
}

// NewWithConfig - Returns a new NetworkSecurityProbe instance with the provided config
func NewWithConfig(config *config.NSPConfig) (*NetworkSecurityProbe, error) {
	var err error
	nsp := NetworkSecurityProbe{
		Config:       config,
		wg:           &sync.WaitGroup{},
		KubeInformer: &informer.SecurityProfileInformer{},
	}
	if config.CLI.KubeConfigPath != "" {
		nsp.KubeConfig, err = clientcmd.BuildConfigFromFlags("", config.CLI.KubeConfigPath)
		if err != nil {
			return nil, err
		}
	} else {
		nsp.KubeConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}
	return &nsp, nil
}

// Start - Starts the network security probe (doesn't block)
func (nsp *NetworkSecurityProbe) Start() error {
	nspLogger.Debugln("network security probe starting ...")
	// Set a unique seed to prepare the generation of IDs
	rand.Seed(time.Now().UnixNano())
	if err := nsp.init(); err != nil {
		return err
	}
	// 1) Load eBPF program
	if err := nsp.loadEBPFProgram(); err != nil {
		return err
	}
	// 2) Start processors
	if err := nsp.startProcessors(); err != nil {
		return err
	}
	// 3) Start monitors
	if err := nsp.startMonitors(); err != nil {
		return err
	}
	// 4) Start k8s informer
	if err := nsp.KubeInformer.Start(); err != nil {
		return err
	}
	return nil
}

// init - Initializes the NetworkSecurityProbe
func (nsp *NetworkSecurityProbe) init() error {
	// Get boot time
	bt, err := host.BootTime()
	if err != nil {
		return err
	}
	nsp.bootTime = time.Unix(int64(bt), 0)
	// Get host netns
	nsp.hostNetns = utils.GetNetnsFromPid(1)
	// Initializes the k8s informer
	if err := nsp.KubeInformer.Init(nsp); err != nil {
		return err
	}
	// Initializes the cache
	nsp.Cache = NewCache(nsp.Config, utils.GetNetnsFromPid(1))
	return nil
}

// loadEBPFProgram - Loads eBPF program
func (nsp *NetworkSecurityProbe) loadEBPFProgram() error {
	// Recover asset
	buf, err := probe.Asset("probe.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}
	reader := bytes.NewReader(buf)
	// Load elf CollectionSpec
	collectionSpec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return errors.Wrap(err, "couldn't load collection spec")
	}
	// Load eBPF program
	nsp.Collection, err = ebpf.NewCollection(collectionSpec)
	if err != nil {
		return errors.Wrap(err, "couldn't load eBPF program")
	}
	nspLogger.Debug("eBPF program loaded")
	// Map the tail call programs
	requestParser, ok := nsp.Collection.Programs["classifier/dns_request_parser"]
	if !ok {
		return errors.Wrap(err, "dns request parser missing")
	}
	requestFD := requestParser.FD()
	requestKey := kernel.DNSRequestParserKey
	responseParser, ok := nsp.Collection.Programs["classifier/dns_response_parser"]
	if !ok {
		return errors.Wrap(err, "dns response parser missing")
	}
	responseFD := responseParser.FD()
	responseKey := kernel.DNSResponseParserKey
	cidrEntry, ok := nsp.Collection.Programs["classifier/cidr_entry"]
	if !ok {
		return errors.Wrap(err, "cidr entry tailcall missing")
	}
	cidrEntryFD := cidrEntry.FD()
	cidrKey := kernel.CIDREntryProgKey
	dnsProgArray, ok := nsp.Collection.Maps["dns_prog_array"]
	if !ok {
		return errors.Wrap(err, "dns prog array not found")
	}
	if err := dnsProgArray.Put(unsafe.Pointer(&requestKey), unsafe.Pointer(&requestFD)); err != nil {
		return errors.Wrap(err, "couldn't insert dns request parser program")
	}
	if err := dnsProgArray.Put(unsafe.Pointer(&responseKey), unsafe.Pointer(&responseFD)); err != nil {
		return errors.Wrap(err, "couldn't insert dns response parser program")
	}
	if err := dnsProgArray.Put(unsafe.Pointer(&cidrKey), unsafe.Pointer(&cidrEntryFD)); err != nil {
		return errors.Wrap(err, "couldn't insert CIDR entry program")
	}
	return nil
}

// startProcessors - Starts event processors
func (nsp *NetworkSecurityProbe) startProcessors() error {
	// Register processors
	nsp.Processors = processor.RegisterProcessors(nsp.Config)
	// Start processors
	for _, p := range processor.ProcessorsList {
		if err := p.Start(nsp); err != nil {
			nspLogger.Errorf("failed to start processor \"%s\": %v", p.GetName(), err)
			return err
		}
	}
	nspLogger.Debugf("%v processor(s) started", len(nsp.Processors))
	return nil
}

// startMonitors - Starts monitors
func (nsp *NetworkSecurityProbe) startMonitors() error {
	// Register monitors
	nsp.Monitors = monitor.RegisterMonitors(nsp.Config)
	nsp.TCMonitors = make(map[int32]model.Monitor)
	// Init monitors
	for _, p := range nsp.Monitors {
		if err := p.Init(nsp); err != nil {
			nspLogger.Errorf("failed to init monitor \"%s\": %v", p.GetName(), err)
			return err
		}
	}
	// Start monitors
	for _, p := range nsp.Monitors {
		if err := p.Start(); err != nil {
			nspLogger.Errorf("failed to start monitor \"%s\": %v", p.GetName(), err)
			return err
		}
	}
	nspLogger.Debugf("%v monitor(s) running", len(nsp.Monitors))
	return nil
}

// Stop - Stops the network security probe and does all the required cleanups
func (nsp *NetworkSecurityProbe) Stop() error {
	// 1) Stop kube informer
	if err := nsp.KubeInformer.Stop(); err != nil {
		nspLogger.Errorf("couldn't stop k8s informer: %s (Ctrl+C to abort)", err)
	}
	// 2) Stop monitors
	for _, p := range nsp.Monitors {
		if err := p.Stop(); err != nil {
			nspLogger.Errorf("couldn't stop monitor \"%s\" (Ctrl+C to abort): %v", p.GetName(), err)
		}
	}
	for _, p := range nsp.TCMonitors {
		if err := p.Stop(); err != nil {
			nspLogger.Errorf("couldn't stop monitor \"%s\" (Ctrl+C to abort): %v", p.GetName(), err)
		}
	}
	// 3) Stop processors
	for _, p := range processor.ProcessorsList {
		if err := p.Stop(); err != nil {
			nspLogger.Errorf("couldn't stop processor \"%s\" (Ctrl+C to abort): %v", p.GetName(), err)
		}
	}
	// 4) Stop module
	if errs := nsp.Collection.Close(); len(errs) > 0 {
		nspLogger.Errorf("couldn't close collection gracefully: %v", errs)
	}
	// Wait for all goroutine to stop
	nsp.wg.Wait()
	nspLogger.Debugln("network security probe done.")
	return nil
}

// DispatchEvent - Dispatches an event to the processors
func (nsp *NetworkSecurityProbe) DispatchEvent(event model.ProbeEvent) {
	// Enrich event
	nsp.Cache.EnrichEvent(event)
	for eventType, processors := range nsp.Processors {
		if eventType == model.AnyEventType || eventType == event.GetEventType() {
			for _, p := range processors {
				select {
				case p.GetEventChan() <- event:
					break
				default:
					nspLogger.Warn("Processor not ready")
					break
				}
			}
		}
	}
}

// SetupDeviceMonitor - Sets up network monitoring on the newly discovered network device
func (nsp *NetworkSecurityProbe) SetupDeviceMonitor(event *model.DeviceEvent) error {
	// Ignore lo interfaces
	if event.DeviceName == "lo" {
		return nil
	}
	// Create a new TC monitor for the interface
	monitor := tcsched.NewTCMonitor(event)
	// Init & Start the new monitor
	if err := monitor.Init(nsp); err != nil {
		nspLogger.Errorf("failed to init monitor \"%s\": %v", monitor.GetName(), err)
		return err
	}
	if err := monitor.Start(); err != nil {
		nspLogger.Errorf("failed to start monitor \"%s\": %v", monitor.GetName(), err)
		return err
	}
	// Add monitor to the list of TC monitors
	nsp.TCMonitors[event.Device.Ifindex] = monitor
	return nil
}

// StopDeviceMonitor - Stops a device monitor
func (nsp *NetworkSecurityProbe) StopDeviceMonitor(event *model.DeviceEvent) error {
	// Stop the device monitor. Changes are the kernel already deleted the qdisc so allow
	// a silent error on deletion.
	monitor, ok := nsp.TCMonitors[event.Device.Ifindex]
	if !ok {
		return nil
	}
	_ = monitor.Stop()
	// Remove monitor from the list of TC monitors
	delete(nsp.TCMonitors, event.Device.Ifindex)
	return nil
}
