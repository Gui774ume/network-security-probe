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
