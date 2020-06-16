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
package keyvalue

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/Gui774ume/network-security-probe/pkg/model/kernel"
	"github.com/Gui774ume/network-security-probe/pkg/utils"
)

// Cookie - Unique cookie used to identify a profile in the kernel
type Cookie uint32

// CookieValue - Cookie structure used as value in hashmaps
type CookieValue struct {
	Cookie Cookie
}

// NewCookie - Returns a new cookie randomly generated
func NewCookie() Cookie {
	return Cookie(rand.Uint32())
}

// CookieListContains - Checks if a cookie is in a list of cookies.
// The functions returns the first id in the map if there is a match.
func CookieListContains(cookies []Cookie, cookie Cookie) int {
	for index, c := range cookies {
		if c == cookie {
			return index
		}
	}
	return -1
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (cv *CookieValue) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	valueB, err := utils.InterfaceToBytes(cv, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&valueB[0]), nil
}

// NewRandomMapName - Returns a new map name randomly generated
func NewRandomMapName() string {
	allowedCharacters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	allowedCharactersLen := len(allowedCharacters)
	nameLength := 15
	b := make([]rune, nameLength)
	for i := range b {
		b[i] = allowedCharacters[rand.Intn(allowedCharactersLen)]
	}
	return string(b)
}

// SecurityProfileActionValue - Security profile action used for value in hashmaps
type SecurityProfileActionValue struct {
	Action kernel.SecurityProfileAction
}

// NetworkAttack - Network attack
type NetworkAttack uint32

const (
	// EmptyNetworkAttack - Used to specify that no attacks was selected. This is the default.
	EmptyNetworkAttack NetworkAttack = 0
	// ArpSpoofing - ARP spoofing network attack
	ArpSpoofing NetworkAttack = 1 << 0
)

func (na NetworkAttack) String() string {
	switch na {
	case EmptyNetworkAttack:
		return "EmptyNetworkAttack"
	case ArpSpoofing:
		return "ArpSpoofing"
	default:
		return "Unknown"
	}
}

// KeyValue - Key value of a rule in a profile
type KeyValue struct {
	Key   Key
	Value interface{}
}

func (kv *KeyValue) String() string {
	return fmt.Sprintf("%v", *kv)
}

// GetMapSection - Returns the map section of the hashmap in which the key-value should live
func (kv *KeyValue) GetMapSection() string {
	return kv.Key.GetMapSection()
}

// GetKey - Returns the unsafe pointer to the key
func (kv *KeyValue) GetKey(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	return kv.Key.GetUnsafePointer(byteOrder)
}

// GetValue - Returns the unsafe pointer to the value
func (kv *KeyValue) GetValue(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	valueB, err := utils.InterfaceToBytes(kv.Value, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&valueB[0]), nil
}

// Key - Key interface
type Key interface {
	GetMapSection() string
	GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error)
	String() string
}

// NetworkAttacksKey - Network attacks key structure
type NetworkAttacksKey struct {
	Cookie Cookie
}

func (nak *NetworkAttacksKey) String() string {
	return fmt.Sprintf("%v", *nak)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (nak *NetworkAttacksKey) GetMapSection() string {
	return "network_attacks_rules"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (nak *NetworkAttacksKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(nak, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// NetworkAttacksValue - Network attack value
type NetworkAttacksValue struct {
	Value NetworkAttack
}

// ActionKey - Action key structure
type ActionKey struct {
	Cookie Cookie
}

func (ak *ActionKey) String() string {
	return fmt.Sprintf("%v", *ak)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (ak *ActionKey) GetMapSection() string {
	return "action_rules"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (ak *ActionKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(ak, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// ActionValue - Action value
type ActionValue struct {
	Action kernel.SecurityProfileAction
}

// ProtocolKey - Protocol key structure
type ProtocolKey struct {
	Cookie      Cookie
	Protocol    uint16
	TrafficType kernel.TrafficType
	Layer       uint8
}

func (pk *ProtocolKey) String() string {
	return fmt.Sprintf("%v", *pk)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (pk *ProtocolKey) GetMapSection() string {
	return "protocol_rules"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (pk *ProtocolKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(pk, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// ProtocolPortKey - ProtocolPortKey key structure
type ProtocolPortKey struct {
	Cookie      Cookie
	Protocol    uint16
	Port        uint16
	TrafficType kernel.TrafficType
}

func (ppk *ProtocolPortKey) String() string {
	return fmt.Sprintf("%v", *ppk)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (ppk *ProtocolPortKey) GetMapSection() string {
	return "protocol_port_rules"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (ppk *ProtocolPortKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(ppk, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// DNSKey - DNS key structure
type DNSKey struct {
	DNS         [kernel.DNSMaxLength]byte
	Cookie      Cookie
	TrafficType kernel.TrafficType
	Layer       uint8
}

func (k *DNSKey) String() string {
	return fmt.Sprintf("%v", *k)
}

// NewDNSKey - Creates a new DNSKey and encodes the domain string appropriately
func NewDNSKey(tt kernel.TrafficType, cookie Cookie, layer uint8, dns string) (*DNSKey, error) {
	encodedName, err := utils.EncodeDNS(dns)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't encode DNS name")
	}
	rep := DNSKey{
		TrafficType: tt,
		Cookie:      cookie,
		Layer:       layer,
		DNS:         encodedName,
	}
	return &rep, nil
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (k *DNSKey) GetMapSection() string {
	return "dns_rules"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (k *DNSKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(k, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// HTTPKey - Http key structure
type HTTPKey struct {
	TrafficType kernel.TrafficType
	Cookie      Cookie
	Method      [kernel.HTTPMaxMethodLength]byte
	URI         [kernel.HTTPMaxURILength]byte
}

func (k *HTTPKey) String() string {
	return fmt.Sprintf("%v", *k)
}

// NewHTTPKey - Creates a new HTTPKey and encodes the method and URI appropriately
func NewHTTPKey(tt kernel.TrafficType, cookie Cookie, method string, uri string) *HTTPKey {
	rep := HTTPKey{
		TrafficType: tt,
		Cookie:      cookie,
		Method:      [kernel.HTTPMaxMethodLength]byte{},
		URI:         [kernel.HTTPMaxURILength]byte{},
	}
	copy(rep.Method[:], method)
	copy(rep.URI[:], uri)
	return &rep
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (k HTTPKey) GetMapSection() string {
	return "http_rules"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (k *HTTPKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(k, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// PIDnsKey - Process namespace key
type PIDnsKey struct {
	NS uint64
}

func (pk *PIDnsKey) String() string {
	return fmt.Sprintf("%v", *pk)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (pk PIDnsKey) GetMapSection() string {
	return "pidns_profile_id"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (pk *PIDnsKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(pk, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// NETnsKey - Process namespace key
type NETnsKey struct {
	NS uint64
}

func (nk *NETnsKey) String() string {
	return fmt.Sprintf("%v", *nk)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (nk NETnsKey) GetMapSection() string {
	return "netns_profile_id"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (nk *NETnsKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(nk, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// PIDKey - Process key
type PIDKey struct {
	PID uint32
}

func (pk *PIDKey) String() string {
	return fmt.Sprintf("%v", *pk)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (pk PIDKey) GetMapSection() string {
	return "pid_binary_id"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (pk *PIDKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(pk, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// BinaryPathKey - Binary path key
type BinaryPathKey struct {
	Cookie Cookie
	Path   [kernel.PathMax]byte
}

func (bpk *BinaryPathKey) String() string {
	return fmt.Sprintf("%v", *bpk)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (bpk BinaryPathKey) GetMapSection() string {
	return "path_binary_id"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (bpk *BinaryPathKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(bpk, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// MapOfMapsKeyValue - Key value of a rule in a profile
type MapOfMapsKeyValue struct {
	MapOfMapsKey      *KeyValue
	MapSectionToClone string
	Keys              []*KeyValue
}

func (momkv *MapOfMapsKeyValue) String() string {
	return fmt.Sprintf("%v", *momkv)
}

// CIDRKey - CIDR key
type CIDRKey struct {
	Prefix uint32
	Data   [16]uint8
}

func (k *CIDRKey) String() string {
	return fmt.Sprintf("%v", *k)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (k *CIDRKey) GetMapSection() string {
	return "cidr_ranges"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (k *CIDRKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(k, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// CIDRRouterKey - CIDR router key
type CIDRRouterKey struct {
	Cookie      Cookie
	IPVersion   kernel.NetworkProtocol
	TrafficType kernel.TrafficType
}

func (k *CIDRRouterKey) String() string {
	return fmt.Sprintf("%v", *k)
}

// GetMapSection - Returns the kernel map section of the hasmap for this key
func (k *CIDRRouterKey) GetMapSection() string {
	return "cidr_rules"
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (k *CIDRRouterKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := utils.InterfaceToBytes(k, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// NewCIDRMapOfMapsKeyValue - Creates a new MapOfMaps key-value for the provided cidrs
func NewCIDRMapOfMapsKeyValue(cidrs []string, cookie Cookie, tt kernel.TrafficType, ipVersion kernel.NetworkProtocol, action interface{}) (*MapOfMapsKeyValue, error) {
	cidrKv := MapOfMapsKeyValue{
		MapOfMapsKey: &KeyValue{
			Key: &CIDRRouterKey{
				TrafficType: tt,
				Cookie:      cookie,
				IPVersion:   ipVersion,
			},
			Value: nil,
		},
		MapSectionToClone: "cidr_ranges",
		Keys:              []*KeyValue{},
	}
	for _, cidr := range cidrs {
		ip, net, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, errors.Wrapf(err, "couldn't parse CIDR %v", cidr)
		}
		prefix, _ := net.Mask.Size()
		cidrk := CIDRKey{
			Prefix: uint32(prefix),
		}
		switch ipVersion {
		case kernel.EthPIP:
			ip4 := ip.To4()
			if ip4 == nil {
				return nil, errors.New("invalid IPv4 addr")
			}
			copy(cidrk.Data[:], ip4)
		case kernel.EthPIPV6:
			ip6 := ip.To16()
			if ip6 == nil {
				return nil, errors.New("invalid IPv6 addr")
			}
			copy(cidrk.Data[:], ip6)
		}
		cidrkv := KeyValue{
			Key:   &cidrk,
			Value: action,
		}
		cidrKv.Keys = append(cidrKv.Keys, &cidrkv)
	}
	return &cidrKv, nil
}
