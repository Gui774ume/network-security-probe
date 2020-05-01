package v1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Gui774ume/network-security-probe/pkg/model/kernel"
	"github.com/Gui774ume/network-security-probe/pkg/processor/profileloader/keyvalue"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityProfile - Security profile k8s resource
type SecurityProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SecurityProfileSpec `json:"spec"`
}

// GenerateRandomIDs - Generate random IDs for the profile
func (sp *SecurityProfile) GenerateRandomIDs() {
	sp.Spec.securityProfileID = keyvalue.NewCookie()
	for _, p := range sp.Spec.ProcessProfiles {
		p.binaryPathID = keyvalue.NewCookie()
	}
}

// GetSecurityProfileCookie - Returns the security profile cookie
func (sp *SecurityProfile) GetSecurityProfileCookie() keyvalue.Cookie {
	return sp.Spec.securityProfileID
}

// SecurityProfileSpec - Specification for the SecurityProfile resource
type SecurityProfileSpec struct {
	securityProfileID    keyvalue.Cookie
	LabelSelector        *metav1.LabelSelector `json:"labelSelector"`
	Actions              []string              `json:"actions"`
	NetworkAttacks       []string              `json:"attacks"`
	DefaultNetworkPolicy NetworkPolicy         `json:"default"`
	ProcessProfiles      []*ProcessProfile     `json:"processes"`
}

// GetActionFlag - Computes the action flag of the security profile
func (sps SecurityProfileSpec) GetActionFlag() kernel.SecurityProfileAction {
	actionFlag := kernel.Ignore
	for _, action := range sps.Actions {
		switch action {
		case "enforce":
			actionFlag = actionFlag | kernel.Enforce
			break
		case "alert":
			actionFlag = actionFlag | kernel.Alert
		case "trace-dns":
			actionFlag = actionFlag | kernel.TraceDNS
		}
	}
	return actionFlag
}

// GetActionKeyValue - Computes the action key-value of the security profile
func (sps SecurityProfileSpec) GetActionKeyValue() *keyvalue.KeyValue {
	return &keyvalue.KeyValue{
		Key: &keyvalue.ActionKey{
			Cookie: sps.securityProfileID,
		},
		Value: keyvalue.ActionValue{
			Action: sps.GetActionFlag(),
		},
	}
}

// GetNetworkAttacksFlag - Computes the network attacks flag of the security profile
func (sps SecurityProfileSpec) GetNetworkAttacksFlag() keyvalue.NetworkAttack {
	flag := keyvalue.EmptyNetworkAttack
	for _, attack := range sps.NetworkAttacks {
		switch attack {
		case "arp-spoofing":
			flag = flag | keyvalue.ArpSpoofing
			break
		}
	}
	return flag
}

// GetNetworkAttacksKeyValue - Computes the network attacks key-value of the security profile
func (sps SecurityProfileSpec) GetNetworkAttacksKeyValue() *keyvalue.KeyValue {
	return &keyvalue.KeyValue{
		Key: &keyvalue.NetworkAttacksKey{
			Cookie: sps.securityProfileID,
		},
		Value: keyvalue.NetworkAttacksValue{
			Value: sps.GetNetworkAttacksFlag(),
		},
	}
}

// GetProfileKeyValues - Returns the profile key-values of the security profile
func (sps SecurityProfileSpec) GetProfileKeyValues() ([]*keyvalue.KeyValue, error) {
	rep := []*keyvalue.KeyValue{
		sps.GetNetworkAttacksKeyValue(),
		sps.GetActionKeyValue(),
	}
	action := keyvalue.SecurityProfileActionValue{
		Action: sps.GetActionFlag(),
	}
	defaultKeys, err := sps.DefaultNetworkPolicy.GetProfileKeyValues(sps.securityProfileID, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, defaultKeys...)
	for _, pp := range sps.ProcessProfiles {
		profileKeys, err := pp.NetworkPolicy.GetProfileKeyValues(pp.binaryPathID, action)
		if err != nil {
			return nil, err
		}
		rep = append(rep, profileKeys...)
	}
	pathKeys, err := sps.GetProfilePathsKeyValues()
	if err != nil {
		return nil, err
	}
	rep = append(rep, pathKeys...)
	return rep, nil
}

// GetProfileMapOfMapsKeyValue - Returns the profile MapOfMaps key-values of the security profile
func (sps SecurityProfileSpec) GetProfileMapOfMapsKeyValue() ([]*keyvalue.MapOfMapsKeyValue, error) {
	rep := []*keyvalue.MapOfMapsKeyValue{}
	action := keyvalue.SecurityProfileActionValue{
		Action: sps.GetActionFlag(),
	}
	defaultKeys, err := sps.DefaultNetworkPolicy.GetProfileMapOfMapsKeyValue(sps.securityProfileID, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, defaultKeys...)
	for _, pp := range sps.ProcessProfiles {
		profileKeys, err := pp.NetworkPolicy.GetProfileMapOfMapsKeyValue(pp.binaryPathID, action)
		if err != nil {
			return nil, err
		}
		rep = append(rep, profileKeys...)
	}
	return rep, nil
}

// GetProfilePathsKeyValues - Returns the BinaryPathKeys of the profile
func (sps SecurityProfileSpec) GetProfilePathsKeyValues() ([]*keyvalue.KeyValue, error) {
	rep := []*keyvalue.KeyValue{}
	for _, pp := range sps.ProcessProfiles {
		rep = append(rep, pp.GetPathKeyValue(sps.securityProfileID))
	}
	return rep, nil
}

// GetProfileNSKeyValues - Returns the namespace key-values of the profile
func (sps SecurityProfileSpec) GetProfileNSKeyValues(netns uint64, pidns uint64) ([]*keyvalue.KeyValue, error) {
	return []*keyvalue.KeyValue{
		&keyvalue.KeyValue{
			Key: &keyvalue.PIDnsKey{
				NS: pidns,
			},
			Value: &keyvalue.CookieValue{
				Cookie: sps.securityProfileID,
			},
		},
		&keyvalue.KeyValue{
			Key: &keyvalue.NETnsKey{
				NS: netns,
			},
			Value: &keyvalue.CookieValue{
				Cookie: sps.securityProfileID,
			},
		},
	}, nil
}

// GetBinaryIDs - Returns the list of binary IDs of the profile
func (sps SecurityProfileSpec) GetBinaryIDs() ([]keyvalue.Cookie, error) {
	rep := []keyvalue.Cookie{}
	for _, pp := range sps.ProcessProfiles {
		rep = append(rep, pp.binaryPathID)
	}
	return rep, nil
}

// IsBinaryIDInProfile - Checks if the profile owns the provided binary ID. If
// there is a match, the function also returns the binary path to which it maps.
func (sps SecurityProfileSpec) IsBinaryIDInProfile(cookie keyvalue.Cookie) (bool, string) {
	for _, pp := range sps.ProcessProfiles {
		if pp.binaryPathID == cookie {
			return true, pp.BinaryPath
		}
	}
	return false, ""
}

// BinaryIDFromPath - Returns the binary_id associated to the provided binary path.
func (sps SecurityProfileSpec) BinaryIDFromPath(path string) keyvalue.Cookie {
	for _, pp := range sps.ProcessProfiles {
		if path == pp.BinaryPath {
			return pp.binaryPathID
		}
	}
	return keyvalue.Cookie(0)
}

// ProcessProfile - Process profile structure
type ProcessProfile struct {
	binaryPathID  keyvalue.Cookie
	BinaryPath    string        `json:"path"`
	NetworkPolicy NetworkPolicy `json:"network"`
}

func (pp *ProcessProfile) String() string {
	return fmt.Sprintf("%v", *pp)
}

// GetPathKeyValue - Returns the BinaryPathKey of the process profile
func (pp *ProcessProfile) GetPathKeyValue(cookie keyvalue.Cookie) *keyvalue.KeyValue {
	pathB := [kernel.PathMax]byte{}
	copy(pathB[:], pp.BinaryPath)
	return &keyvalue.KeyValue{
		Key: &keyvalue.BinaryPathKey{
			Cookie: cookie,
			Path:   pathB,
		},
		Value: &keyvalue.CookieValue{
			Cookie: pp.binaryPathID,
		},
	}
}

// NetworkPolicy - Network policy structure
type NetworkPolicy struct {
	Egress  EgressRule  `json:"egress"`
	Ingress IngressRule `json:"ingress"`
}

// GetProfileMapOfMapsKeyValue - Returns the profile MapOfMaps key-values of the network policy
func (np NetworkPolicy) GetProfileMapOfMapsKeyValue(cookie keyvalue.Cookie, action interface{}) ([]*keyvalue.MapOfMapsKeyValue, error) {
	rep := []*keyvalue.MapOfMapsKeyValue{}
	egressKeys, err := np.Egress.GetProfileMapOfMapsKeyValue(cookie, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, egressKeys...)
	ingressKeys, err := np.Ingress.GetProfileMapOfMapsKeyValue(cookie, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, ingressKeys...)
	return rep, nil
}

// GetProfileKeyValues - Returns the profile key-values of the network policy
func (np NetworkPolicy) GetProfileKeyValues(cookie keyvalue.Cookie, action interface{}) ([]*keyvalue.KeyValue, error) {
	rep := []*keyvalue.KeyValue{}
	egressKeys, err := np.Egress.GetProfileKeyValues(cookie, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, egressKeys...)
	ingressKeys, err := np.Ingress.GetProfileKeyValues(cookie, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, ingressKeys...)
	return rep, nil
}

// EgressRule - Egress rule
type EgressRule struct {
	FQDNs []string `json:"fqdns"`
	CIDR4 []string `json:"cidr4"`
	CIDR6 []string `json:"cidr6"`
	L3    L3Rule   `json:"l3"`
	L4    L4Rule   `json:"l4"`
	L7    L7Rule   `json:"l7"`
}

// GetProfileMapOfMapsKeyValue - Returns the profile MapsOfMaps key-values of the EgressRule
func (er EgressRule) GetProfileMapOfMapsKeyValue(cookie keyvalue.Cookie, action interface{}) ([]*keyvalue.MapOfMapsKeyValue, error) {
	rep := []*keyvalue.MapOfMapsKeyValue{}
	// Compute the CIDR4 MapsOfMapKeyValues
	cidr4Kv, err := keyvalue.NewCIDRMapOfMapsKeyValue(er.CIDR4, cookie, kernel.Egress, kernel.EthPIP, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, cidr4Kv)
	// Compute the CIDR6 MapsOfMapKeyValues
	cidr6Kv, err := keyvalue.NewCIDRMapOfMapsKeyValue(er.CIDR6, cookie, kernel.Egress, kernel.EthPIPV6, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, cidr6Kv)
	return rep, nil
}

// GetProfileKeyValues - Returns the profile key-values of the EgressRule
func (er EgressRule) GetProfileKeyValues(cookie keyvalue.Cookie, action interface{}) ([]*keyvalue.KeyValue, error) {
	rep := []*keyvalue.KeyValue{}
	dnsKeys, err := er.GetDNSKeys(cookie, kernel.Egress, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, dnsKeys...)
	rep = append(rep, er.L3.GetProfileKeyValues(cookie, kernel.Egress, action)...)
	rep = append(rep, er.L4.GetProfileKeyValues(cookie, kernel.Egress, action)...)
	l7Keys, err := er.L7.GetProfileKeyValues(cookie, kernel.Egress, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, l7Keys...)
	return rep, nil
}

// GetDNSKeys - Returns the DNS keys for this rule
func (er EgressRule) GetDNSKeys(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) ([]*keyvalue.KeyValue, error) {
	var err error
	rep := []*keyvalue.KeyValue{}
	for _, fqdn := range er.FQDNs {
		kv := keyvalue.KeyValue{
			Value: action,
		}
		if kv.Key, err = keyvalue.NewDNSKey(
			trafficType,
			cookie,
			3,
			fqdn,
		); err != nil {
			return nil, err
		}
		rep = append(rep, &kv)
	}
	return rep, nil
}

// IngressRule - Ingress rule
type IngressRule struct {
	CIDR4 []string `json:"cidr4"`
	CIDR6 []string `json:"cidr6"`
	L3    L3Rule   `json:"l3"`
	L4    L4Rule   `json:"l4"`
	L7    L7Rule   `json:"l7"`
}

// GetProfileMapOfMapsKeyValue - Returns the profile MapsOfMaps key-values of the IngressRule
func (ir IngressRule) GetProfileMapOfMapsKeyValue(cookie keyvalue.Cookie, action interface{}) ([]*keyvalue.MapOfMapsKeyValue, error) {
	rep := []*keyvalue.MapOfMapsKeyValue{}
	if len(ir.CIDR4) > 0 {
		// Compute the CIDR4 MapsOfMapKeyValues
		cidr4Kv, err := keyvalue.NewCIDRMapOfMapsKeyValue(ir.CIDR4, cookie, kernel.Ingress, kernel.EthPIP, action)
		if err != nil {
			return nil, err
		}
		rep = append(rep, cidr4Kv)
	}
	if len(ir.CIDR6) > 0 {
		// Compute the CIDR6 MapsOfMapKeyValues
		cidr6Kv, err := keyvalue.NewCIDRMapOfMapsKeyValue(ir.CIDR6, cookie, kernel.Ingress, kernel.EthPIPV6, action)
		if err != nil {
			return nil, err
		}
		rep = append(rep, cidr6Kv)
	}
	return rep, nil
}

// GetProfileKeyValues - Returns the profile key-values of the IngressRule
func (ir IngressRule) GetProfileKeyValues(cookie keyvalue.Cookie, action interface{}) ([]*keyvalue.KeyValue, error) {
	rep := []*keyvalue.KeyValue{}
	rep = append(rep, ir.L3.GetProfileKeyValues(cookie, kernel.Ingress, action)...)
	rep = append(rep, ir.L4.GetProfileKeyValues(cookie, kernel.Ingress, action)...)
	l7Keys, err := ir.L7.GetProfileKeyValues(cookie, kernel.Ingress, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, l7Keys...)
	return rep, nil
}

// L3Rule - Layer 3 rule
type L3Rule struct {
	Protocols []string `json:"protocols"`
}

// GetProfileKeyValues - Returns the profile key-values of the L3Rule
func (rule L3Rule) GetProfileKeyValues(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) []*keyvalue.KeyValue {
	rep := []*keyvalue.KeyValue{}
	rep = append(rep, rule.GetProtocolKeys(cookie, trafficType, action)...)
	return rep
}

// GetProtocolKeys - Returns the protocol keys for this rule
func (rule L3Rule) GetProtocolKeys(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) []*keyvalue.KeyValue {
	rep := []*keyvalue.KeyValue{}
	for _, p := range rule.Protocols {
		rep = append(
			rep,
			&keyvalue.KeyValue{
				Key: &keyvalue.ProtocolKey{
					TrafficType: trafficType,
					Cookie:      cookie,
					Protocol:    uint16(kernel.ProfileInputToNetworkProtocol(p)),
					Layer:       3,
				},
				Value: action,
			},
		)
	}
	return rep
}

// L4Rule - Layer 4 rule
type L4Rule struct {
	Protocols     []string             `json:"protocols"`
	ProtocolPorts []L4ProtocolPortRule `json:"protocolPorts"`
}

// L4ProtocolPortRule - L4 protocol-port rule
type L4ProtocolPortRule struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// GetProfileKeyValues - Returns the profile key-values of the L4Rule
func (rule L4Rule) GetProfileKeyValues(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) []*keyvalue.KeyValue {
	rep := []*keyvalue.KeyValue{}
	rep = append(rep, rule.GetProtocolKeys(cookie, trafficType, action)...)
	rep = append(rep, rule.GetProtocolPortKeys(cookie, trafficType, action)...)
	return rep
}

// GetProtocolKeys - Returns the protocol keys for this rule
func (rule L4Rule) GetProtocolKeys(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) []*keyvalue.KeyValue {
	rep := []*keyvalue.KeyValue{}
	for _, p := range rule.Protocols {
		rep = append(
			rep,
			&keyvalue.KeyValue{
				Key: &keyvalue.ProtocolKey{
					TrafficType: trafficType,
					Cookie:      cookie,
					Protocol:    uint16(kernel.ProfileInputToTransportProtocol(p)),
					Layer:       4,
				},
				Value: action,
			},
		)
	}
	return rep
}

// GetProtocolPortKeys - Returns the protocol-port keys for this rule
func (rule L4Rule) GetProtocolPortKeys(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) []*keyvalue.KeyValue {
	rep := []*keyvalue.KeyValue{}
	for _, p := range rule.ProtocolPorts {
		rep = append(
			rep,
			&keyvalue.KeyValue{
				Key: &keyvalue.ProtocolPortKey{
					TrafficType: trafficType,
					Cookie:      cookie,
					Protocol:    uint16(kernel.ProfileInputToTransportProtocol(p.Protocol)),
					Port:        uint16(p.Port),
				},
				Value: action,
			},
		)
	}
	return rep
}

// L7Rule - Layer 7 rule
type L7Rule struct {
	Protocols []string   `json:"protocols"`
	DNS       []string   `json:"dns"`
	HTTP      []HTTPRule `json:"http"`
}

// HTTPRule - HTTP Rules
type HTTPRule struct {
	Method string `json:"method"`
	URI    string `json:"uri"`
}

// GetProfileKeyValues - Returns the profile key-values of the L7Rule
func (rule L7Rule) GetProfileKeyValues(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) ([]*keyvalue.KeyValue, error) {
	rep := []*keyvalue.KeyValue{}
	rep = append(rep, rule.GetProtocolKeys(cookie, trafficType, action)...)
	rep = append(rep, rule.GetHTTPKeys(cookie, trafficType, action)...)
	dnsKeys, err := rule.GetDNSKeys(cookie, trafficType, action)
	if err != nil {
		return nil, err
	}
	rep = append(rep, dnsKeys...)
	return rep, nil
}

// GetProtocolKeys - Returns the protocol keys for this rule
func (rule L7Rule) GetProtocolKeys(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) []*keyvalue.KeyValue {
	rep := []*keyvalue.KeyValue{}
	for _, p := range rule.Protocols {
		rep = append(
			rep,
			&keyvalue.KeyValue{
				Key: &keyvalue.ProtocolKey{
					TrafficType: trafficType,
					Cookie:      cookie,
					Protocol:    uint16(kernel.ProfileInputToApplicationProtocol(p)),
					Layer:       7,
				},
				Value: action,
			},
		)
	}
	return rep
}

// GetHTTPKeys - Returns the HTTP keys for this rule
func (rule L7Rule) GetHTTPKeys(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) []*keyvalue.KeyValue {
	rep := []*keyvalue.KeyValue{}
	for _, p := range rule.HTTP {
		rep = append(
			rep,
			&keyvalue.KeyValue{
				Key: keyvalue.NewHTTPKey(
					trafficType,
					cookie,
					p.Method,
					p.URI,
				),
				Value: action,
			},
		)
	}
	return rep
}

// GetDNSKeys - Returns the DNS keys for this rule
func (rule L7Rule) GetDNSKeys(cookie keyvalue.Cookie, trafficType kernel.TrafficType, action interface{}) ([]*keyvalue.KeyValue, error) {
	var err error
	rep := []*keyvalue.KeyValue{}
	for _, fqdn := range rule.DNS {
		kv := keyvalue.KeyValue{
			Value: action,
		}
		if kv.Key, err = keyvalue.NewDNSKey(
			trafficType,
			cookie,
			7,
			fqdn,
		); err != nil {
			return nil, err
		}
		rep = append(rep, &kv)
	}
	return rep, nil
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityProfileList - List of SecurityProfile resources
type SecurityProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []SecurityProfile `json:"items"`
}
