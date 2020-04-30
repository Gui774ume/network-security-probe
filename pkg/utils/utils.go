package utils

import (
	"C"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/Gui774ume/network-security-probe/pkg/model/kernel"
)

// GetPpid is a fallback to read the parent PID from /proc.
// Some kernel versions, like 4.13.0 return 0 getting the parent PID
// from the current task, so we need to use this fallback to have
// the parent PID in any kernel.
func GetPpid(pid uint32) uint32 {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/status", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		text := sc.Text()
		if strings.Contains(text, "PPid:") {
			f := strings.Fields(text)
			i, _ := strconv.ParseUint(f[len(f)-1], 10, 64)
			return uint32(i)
		}
	}
	return 0
}

// getNamespaceID - Returns the namespace id in brackets
func getNamespaceID(raw string) uint64 {
	i := strings.Index(raw, "[")
	if i > 0 {
		id, err := strconv.ParseUint(raw[i+1:len(raw)-1], 10, 64)
		if err != nil {
			return 0
		}
		return id
	}
	return 0
}

// GetPidnsFromPid - Returns the pid namespace of a process
func GetPidnsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/pid_for_children", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetNetnsFromPid - Returns the network namespace of a process
func GetNetnsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/net", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetUsernsFromPid - Returns the user namespace of a process
func GetUsernsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/user", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetMntnsFromPid - Returns the mount namespace of a process
func GetMntnsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/mnt", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetCgroupFromPid - Returns the cgroup of a process
func GetCgroupFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/cgroup", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetCommFromPid - Returns the comm of a process
func GetCommFromPid(pid uint32) string {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/comm", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return ""
	}
	defer f.Close()
	raw, err := ioutil.ReadAll(f)
	if err != nil {
		return ""
	}
	return strings.Replace(string(raw), "\n", "", -1)
}

// Uint64ToIPv4 - Transforms an uint64 representation of an IPv4 into a string
func Uint64ToIPv4(ipUint uint64) string {
	rep := ""
	for i := 0; i < 4; i++ {
		if i > 0 {
			rep += "."
		}
		rep += fmt.Sprintf("%d", ((ipUint >> uint(i*8)) & 0xff))
	}
	return rep
}

// Uint64sToIPv6 - Transforms an [2]uint64 representation of an IPv6 into a string
func Uint64sToIPv6(ipUints [2]uint64) string {
	rep := ""
	for i, half := range ipUints {
		if i == 1 {
			rep += ":"
		}
		for j := 0; j < 8; j++ {
			b := (half >> uint(j*8)) & 0xff
			if j > 0 && j%2 == 0 {
				rep += ":"
			}
			rep += fmt.Sprintf("%02x", b)
		}
	}
	return rep
}

// Char6ToEth - Transforms an int64 representation of an IPv4 into a string
func Char6ToEth(ethChar [6]byte) string {
	// need to do two bit shifting and “0xff” masking
	rep := ""
	for i, elem := range ethChar {
		if i > 0 {
			rep += ":"
		}
		rep += fmt.Sprintf("%02X", elem)
	}
	return rep
}

// InterfaceToBytes - Tranforms an interface into a C bytes array
func InterfaceToBytes(data interface{}, byteOrder binary.ByteOrder) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, byteOrder, data); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

// EncodeDNS - Returns the DNS packet representation of a domain name
func EncodeDNS(name string) ([kernel.DNSMaxLength]byte, error) {
	buf := [kernel.DNSMaxLength]byte{}
	if len(name)+1 > kernel.DNSMaxLength {
		return buf, errors.New("DNS name too long")
	}
	i := 0
	for _, label := range strings.Split(name, ".") {
		sublen := len(label)
		if sublen > kernel.DNSMaxLabelLength {
			return buf, errors.New("DNS label too long")
		}
		buf[i] = byte(sublen)
		copy(buf[i+1:], label)
		i = i + sublen + 1
	}
	return buf, nil
}

// DecodeDNS - Returns the domain name from its kernel representation
func DecodeDNS(domain [kernel.DNSMaxLength]byte) string {
	rep := ""
	i := 0
	for {
		// Parse label length
		labelLen := int(domain[i])
		if i+1+labelLen >= kernel.DNSMaxLength || labelLen == 0 {
			break
		}
		labelRaw := domain[i+1 : i+1+labelLen]
		if len(rep) == 0 {
			rep = string(labelRaw)
		} else {
			rep = rep + "." + string(labelRaw)
		}
		i += labelLen + 1
	}
	return rep
}

// GetHostByteOrder - Returns the host byte order
func GetHostByteOrder() binary.ByteOrder {
	if isBigEndian() {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}
