package config

import (
	"flag"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var (
	configLogger = logrus.WithField("package", "config")
)

// NSPConfig - Network security probe option
type NSPConfig struct {
	// CLI - CLI parameters
	CLI struct {
		Verbose           logrus.Level
		ConfigPath        string
		KubeConfigPath    string
		ProfileOutputPath string
		Pid               uint32
		Netns             uint64
		DDLogURL          string
		ProcessCacheSize  uint32
	}

	// eBPF - eBPF tunning options
	EBPF struct {
		PerfMapPageCount  int `yaml:"perf_map_page_count" default:"64"`
		KprobeMaxActive   int `yaml:"kprobe_max_active" default:"-1"`
		MapsChannelLength int `yaml:"maps_chanel_length" default:"1000"`
	} `yaml:"ebpf"`

	// MonitoringOptions - Process level network monitoring options
	MonitoringOptions struct {
		// NetworkMonitorTick - This parameter defines how often the eBPF maps containing networking data should be dumped
		NetworkMonitorTick int `yaml:"network_monitor_tick" default:"0"`
		// DNSMonitoring - When activated, the probe will log DNS activity
		DNSMonitoring bool `yaml:"dns_monitoring"`
		// NetworkInterfacesMonitoring - When activated, the probe will log interface activity (registration etc ...)
		NetworkInterfacesMonitoring bool `yaml:"network_interfaces_monitoring"`
		// ConnectionMonitoring - When activated, the probe will log network connections (egress & ingress)
		ConnectionMonitoring bool `yaml:"connection_monitoring"`
	} `yaml:"monitoring_options"`

	// SecurityOptions - Attacks detection options
	SecurityOptions struct {
		// FloodAttacks - When activated, the probe will trigger an alert when a flood attack is detected (SYN flood)
		FloodAttacks SecurityAction `yaml:"flood_attacks"`
		// ARPSpoofing - When activated, the probe will look for ARP spoofing attacks
		ARPSpoofing SecurityAction `yaml:"arp_spoofing"`
		// DNSSpoofing - When activated, the probe will look for DNS spoofing attacks
		DNSSpoofing SecurityAction `yaml:"dns_spoofing"`

		// EgressDomains - List of egress domains with corresponding security action
		EgressDomains map[string]SecurityAction `yaml:"egress_domains"`
		// EgressDefault - Security action taken for unexpected egress domains
		EgressDefault SecurityAction `yaml:"egress_default"`
		// IngressDomains - List of ingress domains with corresponding security action
		IngressDomains map[string]SecurityAction `yamls:"ingress_domains"`
		// IngressDefault - Security action taken for unexpected ingress domains
		IngressDefault SecurityAction `yaml:"ingress_default"`

		// NetworkProtocols - List of expected network protocols (L3) and their security action
		NetworkProtocols map[string]SecurityAction `yaml:"network_protocols"`
		// NetworkProtocolDefault - Security action taken for unexpected network protocols
		NetworkProtocolDefault SecurityAction `yaml:"network_protocol_default"`
		// TransportProtocol - List of expected transport protocols (L4) and their security action
		TransportProtocols map[string]SecurityAction `yaml:"transport_protocols"`
		// TransportProtocolDefault - Security action taken for unexpected transport protocols
		TransportProtocolDefault SecurityAction `yaml:"transport_protocol_default"`
		// ApplicationProtocols - List of expected application protocols (L7) and their security action
		ApplicationProtocols map[string]SecurityAction `yaml:"application_protocols"`
		// ApplicationProtocolDefault - Security action taken for unexpected application protocols
		ApplicationProtocolDefault SecurityAction `yaml:"application_protocol_default"`
	} `yaml:"security_options"`
}

// SecurityAction - A security action defines what the probe should do.
//   - Alert means that an alert will be reported by the probe
//   - Block means that the probe will block the offending connection
//   - Kill means that the offending process will be killed
type SecurityAction struct {
	Alert bool `yaml:"alert" default:"true"`
	Block bool `yaml:"block" default:"false"`
	Kill  bool `yaml:"kill" default:"false"`
}

// parseConfigFromPath - Parses the provided configuration file
func parseConfigFromPath(cfg *NSPConfig, path string) (*NSPConfig, error) {
	if err := ReadConfigFile(path, cfg); err != nil {
		return nil, err
	}
	configLogger.Debugf("configuration file loaded: %s", path)
	return cfg, nil
}

// ReadConfigFile - Read the provided config file and populates the provided config file
func ReadConfigFile(path string, cfg *NSPConfig) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	return decoder.Decode(cfg)
}

// NewConfigFromPath - Returns a configuration parsed from the provided file
func NewConfigFromPath(path string) (*NSPConfig, error) {
	cfg := NSPConfig{}
	return parseConfigFromPath(&cfg, path)
}

// NewConfigFromCLI - Parses command line arguments
func NewConfigFromCLI() (*NSPConfig, error) {
	verbose := flag.Uint("verbose", 5, "verbose level (0 to 6)")
	configPath := flag.String("config", "pkg/config/config.yaml", "config file path")
	profileOutputPath := flag.String("profile", "", "profile output path")
	pid := flag.Uint("pid", 0, "pid filter")
	processCacheSize := flag.Uint("processcachesize", 32770, "process cache size")
	netns := flag.Uint64("netns", 0, "network namespace filter")
	json := flag.Bool("json", false, "output logs will be formated in JSON")
	kubeconfig := flag.String("kubeconfig", "", "the path to the kubeconfig file") //127.0.0.1:10518
	ddLogURL := flag.String("ddlogurl", "127.0.0.1:10518", "config file path")
	flag.Parse()

	cfg := NSPConfig{}

	// Set Verbose level
	cfg.CLI.Verbose = logrus.Level(*verbose)
	logrus.SetLevel(cfg.CLI.Verbose)
	if *json {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:          true,
			TimestampFormat:        "2006-01-02T15:04:05Z",
			DisableLevelTruncation: true,
		})
	}

	// Set paths
	cfg.CLI.ConfigPath = *configPath
	cfg.CLI.ProfileOutputPath = *profileOutputPath
	cfg.CLI.KubeConfigPath = *kubeconfig
	cfg.CLI.DDLogURL = *ddLogURL

	// Set filters
	cfg.CLI.Pid = uint32(*pid)
	cfg.CLI.ProcessCacheSize = uint32(*processCacheSize)
	cfg.CLI.Netns = *netns

	return parseConfigFromPath(&cfg, cfg.CLI.ConfigPath)
}
