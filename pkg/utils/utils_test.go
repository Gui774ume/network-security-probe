package utils

import (
	"reflect"
	"testing"

	"github.com/Gui774ume/network-security-probe/pkg/model/kernel"
)

func TestEncodeDNS(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    [kernel.DNSMaxLength]byte
		wantErr bool
	}{
		{
			"GoogleComEncodeTest",
			args{name: "google.com"},
			[kernel.DNSMaxLength]byte{6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeDNS(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeDNS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EncodeDNS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeDNS(t *testing.T) {
	type args struct {
		domain [kernel.DNSMaxLength]byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"GoogleComDecodeTest",
			args{domain: [kernel.DNSMaxLength]byte{6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109}},
			"google.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecodeDNS(tt.args.domain); got != tt.want {
				t.Errorf("DecodeDNS() = %v, want %v", got, tt.want)
			}
		})
	}
}
