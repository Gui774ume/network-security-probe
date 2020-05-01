package kernel

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// BPFAny - create new element or update existing
	BPFAny = 0
	// BPFNoexist - create new element if it didn't exist
	BPFNoexist = 1
	// BPFExist - update element if it exists
	BPFExist = 2
	// DNSMaxLength - Maximum length of a DNS domain
	DNSMaxLength = 256
	// DNSMaxLabelLength - Maximum length of a DNS label
	DNSMaxLabelLength = 63
	// HTTPMaxURILength - Maximum length of a valid URI for this project
	HTTPMaxURILength = 128
	// HTTPMaxMethodLength - Maximum length of a valid HTTP method for this project
	HTTPMaxMethodLength = 10
	// PathMax - Maximum path length of the paths handled by the project. See ebpf code
	// for more explanation. A production version of this project wouldn't use path in maps
	// anyway, so this is an acceptable limitation for this PoC.
	PathMax = 350
	// DNSRequestParserKey - DNS request parser key in dns_prog_array map
	DNSRequestParserKey = 0
	// DNSResponseParserKey - DNS response parser key in dns_prog_array map
	DNSResponseParserKey = 1
	// CIDREntryProgKey - CIDR entry program key
	CIDREntryProgKey = 2
)

// DNSRecordType - DNS record type
type DNSRecordType uint16

const (
	// ARecord - A record DNS type
	ARecord DNSRecordType = 1
	// AAAARecord - AAAA record DNS type
	AAAARecord DNSRecordType = 0x1c
)

func (drt DNSRecordType) String() string {
	switch drt {
	case ARecord:
		return "a_record"
	case AAAARecord:
		return "aaaa_record"
	default:
		return fmt.Sprintf("DNSRecordType(%v)", uint16(drt))
	}
}

// MarshalJSON - Marshal interface implementation
func (drt DNSRecordType) MarshalJSON() ([]byte, error) {
	return json.Marshal(drt.String())
}

// NetworkAlert - Network alert ID
type NetworkAlert uint8

const (
	// NoProfileAlert - This alert indicates that no profile was found to check the traffic against
	NoProfileAlert NetworkAlert = 1 << 0
	// NoDefaultActionAlert - This alert indicates that no default action was provided for the profile
	NoDefaultActionAlert NetworkAlert = 1 << 1
	// L3Alert - This alert indicates that the profile doesn't allow the detected L3 traffic
	L3Alert NetworkAlert = 1 << 2
	// L4Alert - This alert indicates that the profile doesn't allow the detected L4 traffic
	L4Alert NetworkAlert = 1 << 3
	// L7Alert - This alert indicates that the profile doesn't allow the detected L7 traffic
	L7Alert NetworkAlert = 1 << 4
	// CIDRAlert - This alert indicates that the profile doesn't allow the detected IP source / dest
	CIDRAlert NetworkAlert = 1 << 5
	// DNSAlert - This alert indicates that the profile doesn't allow the detected DNS domain
	DNSAlert NetworkAlert = 1 << 6
	// ARPSpoofingAlert - This alert indicates that an ARP spoofing attempt was detected
	ARPSpoofingAlert NetworkAlert = 1 << 7
)

func (alert NetworkAlert) String() string {
	rep := []string{}
	if alert&NoProfileAlert == NoProfileAlert {
		rep = append(rep, "NoProfileAlert")
	}
	if alert&NoDefaultActionAlert == NoDefaultActionAlert {
		rep = append(rep, "NoDefaultActionAlert")
	}
	if alert&L3Alert == L3Alert {
		rep = append(rep, "L3Alert")
	}
	if alert&L4Alert == L4Alert {
		rep = append(rep, "L4Alert")
	}
	if alert&L7Alert == L7Alert {
		rep = append(rep, "L7Alert")
	}
	if alert&CIDRAlert == CIDRAlert {
		rep = append(rep, "CIDRAlert")
	}
	if alert&DNSAlert == DNSAlert {
		rep = append(rep, "DNSAlert")
	}
	if alert&ARPSpoofingAlert == ARPSpoofingAlert {
		rep = append(rep, "ARPSpoofingAlert")
	}
	return strings.Join(rep, ",")
}

// MarshalJSON - Marshal interface implementation
func (alert NetworkAlert) MarshalJSON() ([]byte, error) {
	return json.Marshal(alert.String())
}

// TrafficType - Traffic type
type TrafficType uint8

const (
	// Egress - Egress traffic type
	Egress TrafficType = 1
	// Ingress TrafficType
	Ingress TrafficType = 2
)

func (tt TrafficType) String() string {
	switch tt {
	case Egress:
		return "egress"
	case Ingress:
		return "ingress"
	default:
		return "unknown"
	}
}

// MarshalJSON - Marshal interface implementation
func (tt TrafficType) MarshalJSON() ([]byte, error) {
	return json.Marshal(tt.String())
}

// InterfaceType - Interface type
type InterfaceType uint8

const (
	// ExternalInterface - Used to designate an external network facing interface
	ExternalInterface InterfaceType = 1
	// ContainerInterface - Used to designate a container veth pair interface
	ContainerInterface InterfaceType = 2
)

func (it InterfaceType) String() string {
	switch it {
	case ExternalInterface:
		return "ExternalInterface"
	case ContainerInterface:
		return "ContainerInterface"
	default:
		return "unknown"
	}
}

// MarshalJSON - Marshal interface implementation
func (it InterfaceType) MarshalJSON() ([]byte, error) {
	return json.Marshal(it.String())
}

// SecurityProfileAction - Security profile action
type SecurityProfileAction uint8

const (
	// Ignore - Any infringement to the profile will be ignored. This is the default.
	Ignore SecurityProfileAction = 0
	// Alert - Any infringement to the profile will trigger an alert.
	Alert SecurityProfileAction = 1 << 0
	// Enforce - Any infringement to the profile will cause traffic to be dropped.
	Enforce SecurityProfileAction = 1 << 1
	// ProfileGeneration - Any infringement to the profile will will be recorded to improve the security profile.
	ProfileGeneration SecurityProfileAction = 1 << 2
	// TraceDNS - Traces any DNS traffic
	TraceDNS SecurityProfileAction = 1 << 3
)

func (action SecurityProfileAction) String() string {
	rep := []string{}
	if action == Ignore {
		return "ignore"
	}
	if action&Alert == Alert {
		rep = append(rep, "alert")
	}
	if action&Enforce == Enforce {
		rep = append(rep, "enforce")
	}
	if action&TraceDNS == TraceDNS {
		rep = append(rep, "trace-dns")
	}
	return strings.Join(rep, ",")
}

// MarshalJSON - Marshal interface implementation
func (action SecurityProfileAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(action.String())
}

// SignalInfo - Signal Info
type SignalInfo int32

const (
	// SIGCHLD - Signal child
	SIGCHLD SignalInfo = 17
)

// SignalInfoToString - Returns a signal as its string representation
func SignalInfoToString(input int32) string {
	si := SignalInfo(input)
	switch si {
	case SIGCHLD:
		return "SIGCHLD"
	default:
		return fmt.Sprintf("SignalInfo(%v)", si)
	}
}

// TransportProtocol - Transport protocols
type TransportProtocol uint8

const (
	// IPProtoIP - Dummy protocol for TCP
	IPProtoIP TransportProtocol = 0
	// IPProtoICMP - Internet Control Message Protocol (IPv4)
	IPProtoICMP TransportProtocol = 1
	// IPProtoIGMP - Internet Group Management Protocol
	IPProtoIGMP TransportProtocol = 2
	// IPProtoIPIP - IPIP tunnels (older KA9Q tunnels use 94)
	IPProtoIPIP TransportProtocol = 4
	// IPProtoTCP - Transmission Control Protocol
	IPProtoTCP TransportProtocol = 6
	// IPProtoEGP - Exterior Gateway Protocol
	IPProtoEGP TransportProtocol = 8
	// IPProtoIGP - Interior Gateway Protocol (any private interior gateway (used by Cisco for their IGRP))
	IPProtoIGP TransportProtocol = 9
	// IPProtoPUP - PUP protocol
	IPProtoPUP TransportProtocol = 12
	// IPProtoUDP - User Datagram Protocol
	IPProtoUDP TransportProtocol = 17
	// IPProtoIDP - XNS IDP protocol
	IPProtoIDP TransportProtocol = 22
	// IPProtoTP - SO Transport Protocol Class 4
	IPProtoTP TransportProtocol = 29
	// IPProtoDCCP - Datagram Congestion Control Protocol
	IPProtoDCCP TransportProtocol = 33
	// IPProtoIPV6 - IPv6-in-IPv4 tunnelling
	IPProtoIPV6 TransportProtocol = 41
	// IPProtoRSVP - RSVP Protocol
	IPProtoRSVP TransportProtocol = 46
	// IPProtoGRE - Cisco GRE tunnels (rfc 1701,1702)
	IPProtoGRE TransportProtocol = 47
	// IPProtoESP - Encapsulation Security Payload protocol
	IPProtoESP TransportProtocol = 50
	// IPProtoAH - Authentication Header protocol
	IPProtoAH TransportProtocol = 51
	// IPProtoICMPV6 - Internet Control Message Protocol (IPv6)
	IPProtoICMPV6 TransportProtocol = 58
	// IPProtoMTP - Multicast Transport Protocol
	IPProtoMTP TransportProtocol = 92
	// IPProtoBEETPH - IP option pseudo header for BEET
	IPProtoBEETPH TransportProtocol = 94
	// IPProtoENCAP - Encapsulation Header
	IPProtoENCAP TransportProtocol = 98
	// IPProtoPIM - Protocol Independent Multicast
	IPProtoPIM TransportProtocol = 103
	// IPProtoCOMP - Compression Header Protocol
	IPProtoCOMP TransportProtocol = 108
	// IPProtoSCTP - Stream Control Transport Protocol
	IPProtoSCTP TransportProtocol = 132
	// IPProtoUDPLITE - UDP-Lite (RFC 3828)
	IPProtoUDPLITE TransportProtocol = 136
	// IPProtoMPLS - MPLS in IP (RFC 4023)
	IPProtoMPLS TransportProtocol = 137
	// IPProtoRAW - Raw IP packets
	IPProtoRAW TransportProtocol = 255
)

func (tp TransportProtocol) String() string {
	switch tp {
	case IPProtoIP:
		return "IPProtoIP"
	case IPProtoICMP:
		return "IPProtoICMP"
	case IPProtoIGMP:
		return "IPProtoIGMP"
	case IPProtoIPIP:
		return "IPProtoIPIP"
	case IPProtoTCP:
		return "IPProtoTCP"
	case IPProtoEGP:
		return "IPProtoEGP"
	case IPProtoIGP:
		return "IPProtoIGP"
	case IPProtoPUP:
		return "IPProtoPUP"
	case IPProtoUDP:
		return "IPProtoUDP"
	case IPProtoIDP:
		return "IPProtoIDP"
	case IPProtoTP:
		return "IPProtoTP"
	case IPProtoDCCP:
		return "IPProtoDCCP"
	case IPProtoIPV6:
		return "IPProtoIPV6"
	case IPProtoRSVP:
		return "IPProtoRSVP"
	case IPProtoGRE:
		return "IPProtoGRE"
	case IPProtoESP:
		return "IPProtoESP"
	case IPProtoAH:
		return "IPProtoAH"
	case IPProtoICMPV6:
		return "IPProtoICMPV6"
	case IPProtoMTP:
		return "IPProtoMTP"
	case IPProtoBEETPH:
		return "IPProtoBEETPH"
	case IPProtoENCAP:
		return "IPProtoENCAP"
	case IPProtoPIM:
		return "IPProtoPIM"
	case IPProtoCOMP:
		return "IPProtoCOMP"
	case IPProtoSCTP:
		return "IPProtoSCTP"
	case IPProtoUDPLITE:
		return "IPProtoUDPLITE"
	case IPProtoMPLS:
		return "IPProtoMPLS"
	case IPProtoRAW:
		return "IPProtoRAW"
	default:
		return fmt.Sprintf("TransportProtocol(%v)", int64(tp))
	}
}

// MarshalJSON - Marshal interface implementation
func (tp TransportProtocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(tp.String())
}

// ProfileInputToTransportProtocol - Transforms a profile input into a transport protocol
func ProfileInputToTransportProtocol(input string) TransportProtocol {
	switch input {
	case "ip":
		return IPProtoIP
	case "icmp":
		return IPProtoICMP
	case "igmp":
		return IPProtoIGMP
	case "ipip":
		return IPProtoIPIP
	case "tcp":
		return IPProtoTCP
	case "egp":
		return IPProtoEGP
	case "igp":
		return IPProtoIGP
	case "pup":
		return IPProtoPUP
	case "udp":
		return IPProtoUDP
	case "idp":
		return IPProtoIDP
	case "tp":
		return IPProtoTP
	case "dccp":
		return IPProtoDCCP
	case "ipv6":
		return IPProtoIPV6
	case "rsvp":
		return IPProtoRSVP
	case "gre":
		return IPProtoGRE
	case "esp":
		return IPProtoESP
	case "ah":
		return IPProtoAH
	case "icmpv6":
		return IPProtoICMPV6
	case "mtp":
		return IPProtoMTP
	case "beetph":
		return IPProtoBEETPH
	case "encap":
		return IPProtoENCAP
	case "pim":
		return IPProtoPIM
	case "comp":
		return IPProtoCOMP
	case "sctp":
		return IPProtoSCTP
	case "udplite":
		return IPProtoUDPLITE
	case "mpls":
		return IPProtoMPLS
	case "raw":
		return IPProtoRAW
	default:
		return IPProtoIP
	}
}

// NetworkProtocol - Network protocols
type NetworkProtocol uint16

const (
	// EthPLOOP - Ethernet Loopback packet
	EthPLOOP NetworkProtocol = 0x0060
	// EthPPUP - Xerox PUP packet
	EthPPUP NetworkProtocol = 0x0200
	// EthPPUPAT - Xerox PUP Addr Trans packet
	EthPPUPAT NetworkProtocol = 0x0201
	// EthPTSN - TSN (IEEE 1722) packet
	EthPTSN NetworkProtocol = 0x22F0
	// EthPIP - Internet Protocol packet
	EthPIP NetworkProtocol = 0x0800
	// EthPX25 - CCITT X.25
	EthPX25 NetworkProtocol = 0x0805
	// EthPARP - Address Resolution packet
	EthPARP NetworkProtocol = 0x0806
	// EthPBPQ - G8BPQ AX.25 Ethernet Packet    [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPBPQ NetworkProtocol = 0x08FF
	// EthPIEEEPUP - Xerox IEEE802.3 PUP packet
	EthPIEEEPUP NetworkProtocol = 0x0a00
	// EthPIEEEPUPAT - Xerox IEEE802.3 PUP Addr Trans packet
	EthPIEEEPUPAT NetworkProtocol = 0x0a01
	// EthPBATMAN - B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPBATMAN NetworkProtocol = 0x4305
	// EthPDEC - DEC Assigned proto
	EthPDEC NetworkProtocol = 0x6000
	// EthPDNADL - DEC DNA Dump/Load
	EthPDNADL NetworkProtocol = 0x6001
	// EthPDNARC - DEC DNA Remote Console
	EthPDNARC NetworkProtocol = 0x6002
	// EthPDNART - DEC DNA Routing
	EthPDNART NetworkProtocol = 0x6003
	// EthPLAT - DEC LAT
	EthPLAT NetworkProtocol = 0x6004
	// EthPDIAG - DEC Diagnostics
	EthPDIAG NetworkProtocol = 0x6005
	// EthPCUST - DEC Customer use
	EthPCUST NetworkProtocol = 0x6006
	// EthPSCA - DEC Systems Comms Arch
	EthPSCA NetworkProtocol = 0x6007
	// EthPTEB - Trans Ether Bridging
	EthPTEB NetworkProtocol = 0x6558
	// EthPRARP - Reverse Addr Res packet
	EthPRARP NetworkProtocol = 0x8035
	// EthPATALK - Appletalk DDP
	EthPATALK NetworkProtocol = 0x809B
	// EthPAARP - Appletalk AARP
	EthPAARP NetworkProtocol = 0x80F3
	// EthP8021Q - 802.1Q VLAN Extended Header
	EthP8021Q NetworkProtocol = 0x8100
	// EthPERSPAN - ERSPAN type II
	EthPERSPAN NetworkProtocol = 0x88BE
	// EthPIPX - IPX over DIX
	EthPIPX NetworkProtocol = 0x8137
	// EthPIPV6 - IPv6 over bluebook
	EthPIPV6 NetworkProtocol = 0x86DD
	// EthPPAUSE - IEEE Pause frames. See 802.3 31B
	EthPPAUSE NetworkProtocol = 0x8808
	// EthPSLOW - Slow Protocol. See 802.3ad 43B
	EthPSLOW NetworkProtocol = 0x8809
	// EthPWCCP - Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt
	EthPWCCP NetworkProtocol = 0x883E
	// EthPMPLSUC - MPLS Unicast traffic
	EthPMPLSUC NetworkProtocol = 0x8847
	// EthPMPLSMC - MPLS Multicast traffic
	EthPMPLSMC NetworkProtocol = 0x8848
	// EthPATMMPOA - MultiProtocol Over ATM
	EthPATMMPOA NetworkProtocol = 0x884c
	// EthPPPPDISC - PPPoE discovery messages
	EthPPPPDISC NetworkProtocol = 0x8863
	// EthPPPPSES - PPPoE session messages
	EthPPPPSES NetworkProtocol = 0x8864
	// EthPLinkCTL - HPNA, wlan link local tunnel
	EthPLinkCTL NetworkProtocol = 0x886c
	// EthPATMFATE - Frame-based ATM Transport over Ethernet
	EthPATMFATE NetworkProtocol = 0x8884
	// EthPPAE - Port Access Entity (IEEE 802.1X)
	EthPPAE NetworkProtocol = 0x888E
	// EthPAOE - ATA over Ethernet
	EthPAOE NetworkProtocol = 0x88A2
	// EthP8021AD - 802.1ad Service VLAN
	EthP8021AD NetworkProtocol = 0x88A8
	// EthP802EX1 - 802.1 Local Experimental 1.
	EthP802EX1 NetworkProtocol = 0x88B5
	// EthPTIPC - TIPC
	EthPTIPC NetworkProtocol = 0x88CA
	// EthPMACSEC - 802.1ae MACsec
	EthPMACSEC NetworkProtocol = 0x88E5
	// EthP8021AH - 802.1ah Backbone Service Tag
	EthP8021AH NetworkProtocol = 0x88E7
	// EthPMVRP - 802.1Q MVRP
	EthPMVRP NetworkProtocol = 0x88F5
	// EthP1588 - IEEE 1588 Timesync
	EthP1588 NetworkProtocol = 0x88F7
	// EthPNCSI - NCSI protocol
	EthPNCSI NetworkProtocol = 0x88F8
	// EthPPRP - IEC 62439-3 PRP/HSRv0
	EthPPRP NetworkProtocol = 0x88FB
	// EthPFCOE - Fibre Channel over Ethernet
	EthPFCOE NetworkProtocol = 0x8906
	// EthPIBOE - Infiniband over Ethernet
	EthPIBOE NetworkProtocol = 0x8915
	// EthPTDLS - TDLS
	EthPTDLS NetworkProtocol = 0x890D
	// EthPFIP - FCoE Initialization Protocol
	EthPFIP NetworkProtocol = 0x8914
	// EthP80221 - IEEE 802.21 Media Independent Handover Protocol
	EthP80221 NetworkProtocol = 0x8917
	// EthPHSR - IEC 62439-3 HSRv1
	EthPHSR NetworkProtocol = 0x892F
	// EthPNSH - Network Service Header
	EthPNSH NetworkProtocol = 0x894F
	// EthPLOOPBACK - Ethernet loopback packet, per IEEE 802.3
	EthPLOOPBACK NetworkProtocol = 0x9000
	// EthPQINQ1 - deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPQINQ1 NetworkProtocol = 0x9100
	// EthPQINQ2 - deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPQINQ2 NetworkProtocol = 0x9200
	// EthPQINQ3 - deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPQINQ3 NetworkProtocol = 0x9300
	// EthPEDSA - Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPEDSA NetworkProtocol = 0xDADA
	// EthPIFE - ForCES inter-FE LFB type
	EthPIFE NetworkProtocol = 0xED3E
	// EthPAFIUCV - IBM afiucv [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPAFIUCV NetworkProtocol = 0xFBFB
	// EthP8023MIN - If the value in the ethernet type is less than this value then the frame is Ethernet II. Else it is 802.3
	EthP8023MIN NetworkProtocol = 0x0600
	// EthPIPV6HopByHop - IPv6 Hop by hop option
	EthPIPV6HopByHop NetworkProtocol = 0x000
	// EthP8023 - Dummy type for 802.3 frames
	EthP8023 NetworkProtocol = 0x0001
	// EthPAX25 - Dummy protocol id for AX.25
	EthPAX25 NetworkProtocol = 0x0002
	// EthPALL - Every packet (be careful!!!)
	EthPALL NetworkProtocol = 0x0003
	// EthP8022 - 802.2 frames
	EthP8022 NetworkProtocol = 0x0004
	// EthPSNAP - Internal only
	EthPSNAP NetworkProtocol = 0x0005
	// EthPDDCMP - DEC DDCMP: Internal only
	EthPDDCMP NetworkProtocol = 0x0006
	// EthPWANPPP - Dummy type for WAN PPP frames*/
	EthPWANPPP NetworkProtocol = 0x0007
	// EthPPPPMP - Dummy type for PPP MP frames
	EthPPPPMP NetworkProtocol = 0x0008
	// EthPLOCALTALK - Localtalk pseudo type
	EthPLOCALTALK NetworkProtocol = 0x0009
	// EthPCAN - CAN: Controller Area Network
	EthPCAN NetworkProtocol = 0x000C
	// EthPCANFD - CANFD: CAN flexible data rate*/
	EthPCANFD NetworkProtocol = 0x000D
	// EthPPPPTALK - Dummy type for Atalk over PPP*/
	EthPPPPTALK NetworkProtocol = 0x0010
	// EthPTR8022 - 802.2 frames
	EthPTR8022 NetworkProtocol = 0x0011
	// EthPMOBITEX - Mobitex (kaz@cafe.net)
	EthPMOBITEX NetworkProtocol = 0x0015
	// EthPCONTROL - Card specific control frames
	EthPCONTROL NetworkProtocol = 0x0016
	// EthPIRDA - Linux-IrDA
	EthPIRDA NetworkProtocol = 0x0017
	// EthPECONET - Acorn Econet
	EthPECONET NetworkProtocol = 0x0018
	// EthPHDLC - HDLC frames
	EthPHDLC NetworkProtocol = 0x0019
	// EthPARCNET - 1A for ArcNet :-)
	EthPARCNET NetworkProtocol = 0x001A
	// EthPDSA - Distributed Switch Arch.
	EthPDSA NetworkProtocol = 0x001B
	// EthPTRAILER - Trailer switch tagging
	EthPTRAILER NetworkProtocol = 0x001C
	// EthPPHONET - Nokia Phonet frames
	EthPPHONET NetworkProtocol = 0x00F5
	// EthPIEEE802154 - IEEE802.15.4 frame
	EthPIEEE802154 NetworkProtocol = 0x00F6
	// EthPCAIF - ST-Ericsson CAIF protocol
	EthPCAIF NetworkProtocol = 0x00F7
	// EthPXDSA - Multiplexed DSA protocol
	EthPXDSA NetworkProtocol = 0x00F8
	// EthPMAP - Qualcomm multiplexing and aggregation protocol
	EthPMAP NetworkProtocol = 0x00F9
)

func (np NetworkProtocol) String() string {
	switch np {
	case EthPLOOP:
		return "EthPLOOP"
	case EthPPUP:
		return "EthPPUP"
	case EthPPUPAT:
		return "EthPPUPAT"
	case EthPTSN:
		return "EthPTSN"
	case EthPIP:
		return "EthPIP"
	case EthPX25:
		return "EthPX25"
	case EthPARP:
		return "EthPARP"
	case EthPBPQ:
		return "EthPBPQ"
	case EthPIEEEPUP:
		return "EthPIEEEPUP"
	case EthPIEEEPUPAT:
		return "EthPIEEEPUPAT"
	case EthPBATMAN:
		return "EthPBATMAN"
	case EthPDEC:
		return "EthPDEC"
	case EthPDNADL:
		return "EthPDNADL"
	case EthPDNARC:
		return "EthPDNARC"
	case EthPDNART:
		return "EthPDNART"
	case EthPLAT:
		return "EthPLAT"
	case EthPDIAG:
		return "EthPDIAG"
	case EthPCUST:
		return "EthPCUST"
	case EthPSCA:
		return "EthPSCA"
	case EthPTEB:
		return "EthPTEB"
	case EthPRARP:
		return "EthPRARP"
	case EthPATALK:
		return "EthPATALK"
	case EthPAARP:
		return "EthPAARP"
	case EthP8021Q:
		return "EthP8021Q"
	case EthPERSPAN:
		return "EthPERSPAN"
	case EthPIPX:
		return "EthPIPX"
	case EthPIPV6:
		return "EthPIPV6"
	case EthPPAUSE:
		return "EthPPAUSE"
	case EthPSLOW:
		return "EthPSLOW"
	case EthPWCCP:
		return "EthPWCCP"
	case EthPMPLSUC:
		return "EthPMPLSUC"
	case EthPMPLSMC:
		return "EthPMPLSMC"
	case EthPATMMPOA:
		return "EthPATMMPOA"
	case EthPPPPDISC:
		return "EthPPPPDISC"
	case EthPPPPSES:
		return "EthPPPPSES"
	case EthPLinkCTL:
		return "EthPLinkCTL"
	case EthPATMFATE:
		return "EthPATMFATE"
	case EthPPAE:
		return "EthPPAE"
	case EthPAOE:
		return "EthPAOE"
	case EthP8021AD:
		return "EthP8021AD"
	case EthP802EX1:
		return "EthP802EX1"
	case EthPTIPC:
		return "EthPTIPC"
	case EthPMACSEC:
		return "EthPMACSEC"
	case EthP8021AH:
		return "EthP8021AH"
	case EthPMVRP:
		return "EthPMVRP"
	case EthP1588:
		return "EthP1588"
	case EthPNCSI:
		return "EthPNCSI"
	case EthPPRP:
		return "EthPPRP"
	case EthPFCOE:
		return "EthPFCOE"
	case EthPIBOE:
		return "EthPIBOE"
	case EthPTDLS:
		return "EthPTDLS"
	case EthPFIP:
		return "EthPFIP"
	case EthP80221:
		return "EthP80221"
	case EthPHSR:
		return "EthPHSR"
	case EthPNSH:
		return "EthPNSH"
	case EthPLOOPBACK:
		return "EthPLOOPBACK"
	case EthPQINQ1:
		return "EthPQINQ1"
	case EthPQINQ2:
		return "EthPQINQ2"
	case EthPQINQ3:
		return "EthPQINQ3"
	case EthPEDSA:
		return "EthPEDSA"
	case EthPIFE:
		return "EthPIFE"
	case EthPAFIUCV:
		return "EthPAFIUCV"
	case EthP8023MIN:
		return "EthP8023MIN"
	case EthPIPV6HopByHop:
		return "EthPIPV6HopByHop"
	case EthP8023:
		return "EthP8023"
	case EthPAX25:
		return "EthPAX25"
	case EthPALL:
		return "EthPALL"
	case EthP8022:
		return "EthP8022"
	case EthPSNAP:
		return "EthPSNAP"
	case EthPDDCMP:
		return "EthPDDCMP"
	case EthPWANPPP:
		return "EthPWANPPP"
	case EthPPPPMP:
		return "EthPPPPMP"
	case EthPLOCALTALK:
		return "EthPLOCALTALK"
	case EthPCAN:
		return "EthPCAN"
	case EthPCANFD:
		return "EthPCANFD"
	case EthPPPPTALK:
		return "EthPPPPTALK"
	case EthPTR8022:
		return "EthPTR8022"
	case EthPMOBITEX:
		return "EthPMOBITEX"
	case EthPCONTROL:
		return "EthPCONTROL"
	case EthPIRDA:
		return "EthPIRDA"
	case EthPECONET:
		return "EthPECONET"
	case EthPHDLC:
		return "EthPHDLC"
	case EthPARCNET:
		return "EthPARCNET"
	case EthPDSA:
		return "EthPDSA"
	case EthPTRAILER:
		return "EthPTRAILER"
	case EthPPHONET:
		return "EthPPHONET"
	case EthPIEEE802154:
		return "EthPIEEE802154"
	case EthPCAIF:
		return "EthPCAIF"
	case EthPXDSA:
		return "EthPXDSA"
	case EthPMAP:
		return "EthPMAP"
	default:
		return fmt.Sprintf("NetworkProtocol(%v)", uint64(np))
	}
}

// MarshalJSON - Marshal interface implementation
func (np NetworkProtocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(np.String())
}

// ProfileInputToNetworkProtocol - Transforms a profile input into a network protocol
func ProfileInputToNetworkProtocol(input string) NetworkProtocol {
	switch input {
	case "loop":
		return EthPLOOP
	case "pup":
		return EthPPUP
	case "pupat":
		return EthPPUPAT
	case "tsn":
		return EthPTSN
	case "ipv4":
		return EthPIP
	case "x25":
		return EthPX25
	case "arp":
		return EthPARP
	case "bpq":
		return EthPBPQ
	case "ieeepup":
		return EthPIEEEPUP
	case "ieeepupat":
		return EthPIEEEPUPAT
	case "batman":
		return EthPBATMAN
	case "dec":
		return EthPDEC
	case "dnadl":
		return EthPDNADL
	case "dnarc":
		return EthPDNARC
	case "dnart":
		return EthPDNART
	case "lat":
		return EthPLAT
	case "diag":
		return EthPDIAG
	case "cust":
		return EthPCUST
	case "sca":
		return EthPSCA
	case "teb":
		return EthPTEB
	case "rarp":
		return EthPRARP
	case "atalk":
		return EthPATALK
	case "aarp":
		return EthPAARP
	case "8021q":
		return EthP8021Q
	case "erspan":
		return EthPERSPAN
	case "ipx":
		return EthPIPX
	case "ipv6":
		return EthPIPV6
	case "pause":
		return EthPPAUSE
	case "slow":
		return EthPSLOW
	case "wccp":
		return EthPWCCP
	case "mplsuc":
		return EthPMPLSUC
	case "mplsmc":
		return EthPMPLSMC
	case "atmmpoa":
		return EthPATMMPOA
	case "pppdisc":
		return EthPPPPDISC
	case "pppses":
		return EthPPPPSES
	case "linkctl":
		return EthPLinkCTL
	case "atmfate":
		return EthPATMFATE
	case "pae":
		return EthPPAE
	case "aoe":
		return EthPAOE
	case "8021ad":
		return EthP8021AD
	case "802ex1":
		return EthP802EX1
	case "tipc":
		return EthPTIPC
	case "macsec":
		return EthPMACSEC
	case "8021ah":
		return EthP8021AH
	case "mvrp":
		return EthPMVRP
	case "1588":
		return EthP1588
	case "ncsi":
		return EthPNCSI
	case "prp":
		return EthPPRP
	case "fcoe":
		return EthPFCOE
	case "iboe":
		return EthPIBOE
	case "tdls":
		return EthPTDLS
	case "fip":
		return EthPFIP
	case "80221":
		return EthP80221
	case "hsr":
		return EthPHSR
	case "nsh":
		return EthPNSH
	case "loopback":
		return EthPLOOPBACK
	case "qinq1":
		return EthPQINQ1
	case "qinq2":
		return EthPQINQ2
	case "qinq3":
		return EthPQINQ3
	case "edsa":
		return EthPEDSA
	case "ife":
		return EthPIFE
	case "afiucv":
		return EthPAFIUCV
	case "8023min":
		return EthP8023MIN
	case "ipv6hopbyhop":
		return EthPIPV6HopByHop
	case "8023":
		return EthP8023
	case "ax25":
		return EthPAX25
	case "all":
		return EthPALL
	case "8022":
		return EthP8022
	case "snap":
		return EthPSNAP
	case "ddcmp":
		return EthPDDCMP
	case "wanppp":
		return EthPWANPPP
	case "pppmp":
		return EthPPPPMP
	case "localtalk":
		return EthPLOCALTALK
	case "can":
		return EthPCAN
	case "canfd":
		return EthPCANFD
	case "ppptalk":
		return EthPPPPTALK
	case "tr8022":
		return EthPTR8022
	case "mobitex":
		return EthPMOBITEX
	case "control":
		return EthPCONTROL
	case "irda":
		return EthPIRDA
	case "econet":
		return EthPECONET
	case "hdlc":
		return EthPHDLC
	case "arcnet":
		return EthPARCNET
	case "dsa":
		return EthPDSA
	case "trailer":
		return EthPTRAILER
	case "phonet":
		return EthPPHONET
	case "ieee802154":
		return EthPIEEE802154
	case "caif":
		return EthPCAIF
	case "xdsa":
		return EthPXDSA
	case "map":
		return EthPMAP
	default:
		return NetworkProtocol(0)
	}
}

// ApplicationProtocol - Application protocols
type ApplicationProtocol uint16

const (
	_ = iota
	// Any - Allows all L7 protocols
	Any ApplicationProtocol = iota
	// DNS - DNS protocol
	DNS
	// HTTP - Http protocol
	HTTP
	// HTTPS - Https protocol
	HTTPS
)

func (ap ApplicationProtocol) String() string {
	switch ap {
	case DNS:
		return "DNS"
	case HTTP:
		return "HTTP"
	case HTTPS:
		return "HTTPS"
	default:
		return "unknown"
	}
}

// MarshalJSON - Marshal interface implementation
func (ap ApplicationProtocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(ap.String())
}

// ProfileInputToApplicationProtocol - Transforms a profile input into an application protocol
func ProfileInputToApplicationProtocol(input string) ApplicationProtocol {
	switch input {
	case "dns":
		return DNS
	case "http":
		return HTTP
	case "https":
		return HTTPS
	case "*":
		return Any
	default:
		return ApplicationProtocol(0)
	}
}

// SocketFamily - Socket family enum
type SocketFamily int32

const (
	// AFUnspec - AF Unspecified
	AFUnspec SocketFamily = 0
	// AFUnix - AF Unix
	AFUnix SocketFamily = 1
	// AFLocal - AF Local
	AFLocal SocketFamily = AFUnix
	// AFInet - AF Inet
	AFInet SocketFamily = 2
	// AFAX25 - AFAX25
	AFAX25 SocketFamily = 3
	// AFIPX - AFIPX
	AFIPX SocketFamily = 4
	// AFAPPLETALK - AFAPPLETALK
	AFAPPLETALK SocketFamily = 5
	// AFNetRom - AFNetRom
	AFNetRom SocketFamily = 6
	// AFBridge - AFBridge
	AFBridge SocketFamily = 7
	// AFATMPVC - AFATMPVC
	AFATMPVC SocketFamily = 8
	// AFX25 - AFX25
	AFX25 SocketFamily = 9
	// AFInet6 - AFInet6
	AFInet6 SocketFamily = 10
	// AFRose - AFRose
	AFRose SocketFamily = 11
	// AFDECnet - AFDECnet
	AFDECnet SocketFamily = 12
	// AFNetBEUI - AFNetBEUI
	AFNetBEUI SocketFamily = 13
	// AFSecurity - AFSecurity
	AFSecurity SocketFamily = 14
	// AFKey - AFKey
	AFKey SocketFamily = 15
	// AFNetLink - AFNetLink
	AFNetLink SocketFamily = 16
	// AFRoute - AFRoute
	AFRoute SocketFamily = AFNetLink
	// AFPacket - AFPacket
	AFPacket SocketFamily = 17
	// AFASH - AFASH
	AFASH SocketFamily = 18
	// AFECONET - AFECONET
	AFECONET SocketFamily = 19
	// AFATMSVC - AFATMSVC
	AFATMSVC SocketFamily = 20
	// AFRDS - AFRDS
	AFRDS SocketFamily = 21
	// AFSNA - AFSNA
	AFSNA SocketFamily = 22
	// AFIRDA - AFIRDA
	AFIRDA SocketFamily = 23
	// AFPPPOX - AFPPPOX
	AFPPPOX SocketFamily = 24
	// AFWanPipe - AFWanPipe
	AFWanPipe SocketFamily = 25
	// AFLLC - AFLLC
	AFLLC SocketFamily = 26
	// AFIB - AFIB
	AFIB SocketFamily = 27
	// AFMPLS - AFMPLS
	AFMPLS SocketFamily = 28
	// AFCAN - AFCAN
	AFCAN SocketFamily = 29
	// AFTIPC - AFTIPC
	AFTIPC SocketFamily = 30
	// AFBluetooth - AFBluetooth
	AFBluetooth SocketFamily = 31
	// AFIUCV - AFIUCV
	AFIUCV SocketFamily = 32
	// AFRXRPC - AFRXRPC
	AFRXRPC SocketFamily = 33
	// AFISDN - AFISDN
	AFISDN SocketFamily = 34
	// AFPHONET - AFPHONET
	AFPHONET SocketFamily = 35
	// AFIEEE802154 - AFIEEE802154
	AFIEEE802154 SocketFamily = 36
	// AFCAIF - AFCAIF
	AFCAIF SocketFamily = 37
	// AFALG - AFALG
	AFALG SocketFamily = 38
	// AFNFC - AFNFC
	AFNFC SocketFamily = 39
	// AFVSOCK - AFVSOCK
	AFVSOCK SocketFamily = 40
	// AFKCM - AFKCM
	AFKCM SocketFamily = 41
	// AFQIPCRTR - AFQIPCRTR
	AFQIPCRTR SocketFamily = 42
	// AFSMC - AFSMC
	AFSMC SocketFamily = 43
	// AFXDP - AFXDP
	AFXDP SocketFamily = 44
	// AFMAX - AFMAX
	AFMAX SocketFamily = 45
)

// SocketFamilyToString - Returns a socket family as its string representation
func (sf SocketFamily) String() string {
	switch sf {
	case AFUnspec:
		return "AFUnspec"
	case AFUnix:
		return "AFUnix"
	case AFInet:
		return "AFInet"
	case AFAX25:
		return "AFAX25"
	case AFIPX:
		return "AFIPX"
	case AFAPPLETALK:
		return "AFAPPLETALK"
	case AFNetRom:
		return "AFNetRom"
	case AFBridge:
		return "AFBridge"
	case AFATMPVC:
		return "AFATMPVC"
	case AFX25:
		return "AFX25"
	case AFInet6:
		return "AFInet6"
	case AFRose:
		return "AFRose"
	case AFDECnet:
		return "AFDECnet"
	case AFNetBEUI:
		return "AFNetBEUI"
	case AFSecurity:
		return "AFSecurity"
	case AFKey:
		return "AFKey"
	case AFNetLink:
		return "AFNetLink"
	case AFPacket:
		return "AFPacket"
	case AFASH:
		return "AFASH"
	case AFECONET:
		return "AFECONET"
	case AFATMSVC:
		return "AFATMSVC"
	case AFRDS:
		return "AFRDS"
	case AFSNA:
		return "AFSNA"
	case AFIRDA:
		return "AFIRDA"
	case AFPPPOX:
		return "AFPPPOX"
	case AFWanPipe:
		return "AFWanPipe"
	case AFLLC:
		return "AFLLC"
	case AFIB:
		return "AFIB"
	case AFMPLS:
		return "AFMPLS"
	case AFCAN:
		return "AFCAN"
	case AFTIPC:
		return "AFTIPC"
	case AFBluetooth:
		return "AFBluetooth"
	case AFIUCV:
		return "AFIUCV"
	case AFRXRPC:
		return "AFRXRPC"
	case AFISDN:
		return "AFISDN"
	case AFPHONET:
		return "AFPHONET"
	case AFIEEE802154:
		return "AFIEEE802154"
	case AFCAIF:
		return "AFCAIF"
	case AFALG:
		return "AFALG"
	case AFNFC:
		return "AFNFC"
	case AFVSOCK:
		return "AFVSOCK"
	case AFKCM:
		return "AFKCM"
	case AFQIPCRTR:
		return "AFQIPCRTR"
	case AFSMC:
		return "AFSMC"
	case AFXDP:
		return "AFXDP"
	case AFMAX:
		return "AFMAX"
	default:
		return fmt.Sprintf("SocketFamily(%v)", int32(sf))
	}
}

// MarshalJSON - Marshal interface implementation
func (sf SocketFamily) MarshalJSON() ([]byte, error) {
	return json.Marshal(sf.String())
}
