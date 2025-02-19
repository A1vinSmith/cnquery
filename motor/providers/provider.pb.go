// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.7
// source: provider.proto

package providers

import (
	vault "go.mondoo.com/cnquery/motor/vault"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ProviderType int32

const (
	ProviderType_LOCAL_OS                ProviderType = 0
	ProviderType_DOCKER_ENGINE_IMAGE     ProviderType = 1
	ProviderType_DOCKER_ENGINE_CONTAINER ProviderType = 2
	ProviderType_SSH                     ProviderType = 3
	ProviderType_WINRM                   ProviderType = 4
	ProviderType_AWS_SSM_RUN_COMMAND     ProviderType = 5
	ProviderType_CONTAINER_REGISTRY      ProviderType = 6
	ProviderType_TAR                     ProviderType = 7
	ProviderType_MOCK                    ProviderType = 8
	ProviderType_VSPHERE                 ProviderType = 9
	ProviderType_ARISTAEOS               ProviderType = 10
	ProviderType_AWS                     ProviderType = 12
	ProviderType_GCP                     ProviderType = 13
	ProviderType_AZURE                   ProviderType = 14
	ProviderType_MS365                   ProviderType = 15
	ProviderType_IPMI                    ProviderType = 16
	ProviderType_VSPHERE_VM              ProviderType = 17
	ProviderType_FS                      ProviderType = 18
	ProviderType_K8S                     ProviderType = 19
	ProviderType_EQUINIX_METAL           ProviderType = 20
	ProviderType_DOCKER                  ProviderType = 21 // unspecified if this is a container or image
	ProviderType_GITHUB                  ProviderType = 22
	ProviderType_VAGRANT                 ProviderType = 23
	ProviderType_AWS_EC2_EBS             ProviderType = 24
	ProviderType_GITLAB                  ProviderType = 25
	ProviderType_TERRAFORM               ProviderType = 26
	ProviderType_HOST                    ProviderType = 27
	ProviderType_UNKNOWN                 ProviderType = 28
)

// Enum value maps for ProviderType.
var (
	ProviderType_name = map[int32]string{
		0:  "LOCAL_OS",
		1:  "DOCKER_ENGINE_IMAGE",
		2:  "DOCKER_ENGINE_CONTAINER",
		3:  "SSH",
		4:  "WINRM",
		5:  "AWS_SSM_RUN_COMMAND",
		6:  "CONTAINER_REGISTRY",
		7:  "TAR",
		8:  "MOCK",
		9:  "VSPHERE",
		10: "ARISTAEOS",
		12: "AWS",
		13: "GCP",
		14: "AZURE",
		15: "MS365",
		16: "IPMI",
		17: "VSPHERE_VM",
		18: "FS",
		19: "K8S",
		20: "EQUINIX_METAL",
		21: "DOCKER",
		22: "GITHUB",
		23: "VAGRANT",
		24: "AWS_EC2_EBS",
		25: "GITLAB",
		26: "TERRAFORM",
		27: "HOST",
		28: "UNKNOWN",
	}
	ProviderType_value = map[string]int32{
		"LOCAL_OS":                0,
		"DOCKER_ENGINE_IMAGE":     1,
		"DOCKER_ENGINE_CONTAINER": 2,
		"SSH":                     3,
		"WINRM":                   4,
		"AWS_SSM_RUN_COMMAND":     5,
		"CONTAINER_REGISTRY":      6,
		"TAR":                     7,
		"MOCK":                    8,
		"VSPHERE":                 9,
		"ARISTAEOS":               10,
		"AWS":                     12,
		"GCP":                     13,
		"AZURE":                   14,
		"MS365":                   15,
		"IPMI":                    16,
		"VSPHERE_VM":              17,
		"FS":                      18,
		"K8S":                     19,
		"EQUINIX_METAL":           20,
		"DOCKER":                  21,
		"GITHUB":                  22,
		"VAGRANT":                 23,
		"AWS_EC2_EBS":             24,
		"GITLAB":                  25,
		"TERRAFORM":               26,
		"HOST":                    27,
		"UNKNOWN":                 28,
	}
)

func (x ProviderType) Enum() *ProviderType {
	p := new(ProviderType)
	*p = x
	return p
}

func (x ProviderType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProviderType) Descriptor() protoreflect.EnumDescriptor {
	return file_provider_proto_enumTypes[0].Descriptor()
}

func (ProviderType) Type() protoreflect.EnumType {
	return &file_provider_proto_enumTypes[0]
}

func (x ProviderType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ProviderType.Descriptor instead.
func (ProviderType) EnumDescriptor() ([]byte, []int) {
	return file_provider_proto_rawDescGZIP(), []int{0}
}

type Kind int32

const (
	Kind_KIND_UNKNOWN Kind = 0
	// at rest
	Kind_KIND_VIRTUAL_MACHINE_IMAGE Kind = 1
	Kind_KIND_CONTAINER_IMAGE       Kind = 2
	Kind_KIND_CODE                  Kind = 3
	Kind_KIND_PACKAGE               Kind = 4
	// in motion
	Kind_KIND_VIRTUAL_MACHINE Kind = 5
	Kind_KIND_CONTAINER       Kind = 6
	Kind_KIND_PROCESS         Kind = 7
	Kind_KIND_API             Kind = 8
	Kind_KIND_BARE_METAL      Kind = 9
	Kind_KIND_NETWORK         Kind = 10
	Kind_KIND_K8S_OBJECT      Kind = 11
)

// Enum value maps for Kind.
var (
	Kind_name = map[int32]string{
		0:  "KIND_UNKNOWN",
		1:  "KIND_VIRTUAL_MACHINE_IMAGE",
		2:  "KIND_CONTAINER_IMAGE",
		3:  "KIND_CODE",
		4:  "KIND_PACKAGE",
		5:  "KIND_VIRTUAL_MACHINE",
		6:  "KIND_CONTAINER",
		7:  "KIND_PROCESS",
		8:  "KIND_API",
		9:  "KIND_BARE_METAL",
		10: "KIND_NETWORK",
		11: "KIND_K8S_OBJECT",
	}
	Kind_value = map[string]int32{
		"KIND_UNKNOWN":               0,
		"KIND_VIRTUAL_MACHINE_IMAGE": 1,
		"KIND_CONTAINER_IMAGE":       2,
		"KIND_CODE":                  3,
		"KIND_PACKAGE":               4,
		"KIND_VIRTUAL_MACHINE":       5,
		"KIND_CONTAINER":             6,
		"KIND_PROCESS":               7,
		"KIND_API":                   8,
		"KIND_BARE_METAL":            9,
		"KIND_NETWORK":               10,
		"KIND_K8S_OBJECT":            11,
	}
)

func (x Kind) Enum() *Kind {
	p := new(Kind)
	*p = x
	return p
}

func (x Kind) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Kind) Descriptor() protoreflect.EnumDescriptor {
	return file_provider_proto_enumTypes[1].Descriptor()
}

func (Kind) Type() protoreflect.EnumType {
	return &file_provider_proto_enumTypes[1]
}

func (x Kind) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Kind.Descriptor instead.
func (Kind) EnumDescriptor() ([]byte, []int) {
	return file_provider_proto_rawDescGZIP(), []int{1}
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Backend ProviderType `protobuf:"varint,1,opt,name=backend,proto3,enum=cnquery.motor.providers.v1.ProviderType" json:"backend,omitempty"`
	Host    string       `protobuf:"bytes,2,opt,name=host,proto3" json:"host,omitempty"`
	// Ports are not int by default, eg. docker://centos:latest parses a string as port
	// Therefore it is up to the provider to convert the port to what they need
	Port int32  `protobuf:"varint,3,opt,name=port,proto3" json:"port,omitempty"`
	Path string `protobuf:"bytes,4,opt,name=path,proto3" json:"path,omitempty"`
	// credentials available for this provider configuration
	Credentials []*vault.Credential `protobuf:"bytes,11,rep,name=credentials,proto3" json:"credentials,omitempty"`
	Insecure    bool                `protobuf:"varint,8,opt,name=insecure,proto3" json:"insecure,omitempty"` // disable ssl/tls checks
	Sudo        *Sudo               `protobuf:"bytes,21,opt,name=sudo,proto3" json:"sudo,omitempty"`
	Record      bool                `protobuf:"varint,22,opt,name=record,proto3" json:"record,omitempty"`
	Options     map[string]string   `protobuf:"bytes,23,rep,name=options,proto3" json:"options,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// flags for additional asset discovery
	Discover *Discovery `protobuf:"bytes,27,opt,name=discover,proto3" json:"discover,omitempty"`
	// additional platform information, passed-through
	Kind    Kind   `protobuf:"varint,24,opt,name=kind,proto3,enum=cnquery.motor.providers.v1.Kind" json:"kind,omitempty"`
	Runtime string `protobuf:"bytes,25,opt,name=runtime,proto3" json:"runtime,omitempty"`
	// configuration to uniquely identify an specific asset for multi-asset api connection
	PlatformId string `protobuf:"bytes,26,opt,name=platform_id,json=platformId,proto3" json:"platform_id,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_provider_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_provider_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_provider_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetBackend() ProviderType {
	if x != nil {
		return x.Backend
	}
	return ProviderType_LOCAL_OS
}

func (x *Config) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *Config) GetPort() int32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *Config) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *Config) GetCredentials() []*vault.Credential {
	if x != nil {
		return x.Credentials
	}
	return nil
}

func (x *Config) GetInsecure() bool {
	if x != nil {
		return x.Insecure
	}
	return false
}

func (x *Config) GetSudo() *Sudo {
	if x != nil {
		return x.Sudo
	}
	return nil
}

func (x *Config) GetRecord() bool {
	if x != nil {
		return x.Record
	}
	return false
}

func (x *Config) GetOptions() map[string]string {
	if x != nil {
		return x.Options
	}
	return nil
}

func (x *Config) GetDiscover() *Discovery {
	if x != nil {
		return x.Discover
	}
	return nil
}

func (x *Config) GetKind() Kind {
	if x != nil {
		return x.Kind
	}
	return Kind_KIND_UNKNOWN
}

func (x *Config) GetRuntime() string {
	if x != nil {
		return x.Runtime
	}
	return ""
}

func (x *Config) GetPlatformId() string {
	if x != nil {
		return x.PlatformId
	}
	return ""
}

type Sudo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Active bool   `protobuf:"varint,1,opt,name=active,proto3" json:"active,omitempty"`
	User   string `protobuf:"bytes,2,opt,name=user,proto3" json:"user,omitempty"`
	Shell  string `protobuf:"bytes,3,opt,name=shell,proto3" json:"shell,omitempty"`
}

func (x *Sudo) Reset() {
	*x = Sudo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_provider_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Sudo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Sudo) ProtoMessage() {}

func (x *Sudo) ProtoReflect() protoreflect.Message {
	mi := &file_provider_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Sudo.ProtoReflect.Descriptor instead.
func (*Sudo) Descriptor() ([]byte, []int) {
	return file_provider_proto_rawDescGZIP(), []int{1}
}

func (x *Sudo) GetActive() bool {
	if x != nil {
		return x.Active
	}
	return false
}

func (x *Sudo) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *Sudo) GetShell() string {
	if x != nil {
		return x.Shell
	}
	return ""
}

type Discovery struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Targets []string          `protobuf:"bytes,1,rep,name=targets,proto3" json:"targets,omitempty"`
	Filter  map[string]string `protobuf:"bytes,2,rep,name=filter,proto3" json:"filter,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Discovery) Reset() {
	*x = Discovery{}
	if protoimpl.UnsafeEnabled {
		mi := &file_provider_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Discovery) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Discovery) ProtoMessage() {}

func (x *Discovery) ProtoReflect() protoreflect.Message {
	mi := &file_provider_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Discovery.ProtoReflect.Descriptor instead.
func (*Discovery) Descriptor() ([]byte, []int) {
	return file_provider_proto_rawDescGZIP(), []int{2}
}

func (x *Discovery) GetTargets() []string {
	if x != nil {
		return x.Targets
	}
	return nil
}

func (x *Discovery) GetFilter() map[string]string {
	if x != nil {
		return x.Filter
	}
	return nil
}

var File_provider_proto protoreflect.FileDescriptor

var file_provider_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x1a, 0x63, 0x6e, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x6d, 0x6f, 0x74, 0x6f, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x17, 0x6d, 0x6f,
	0x74, 0x6f, 0x72, 0x2f, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2f, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x91, 0x05, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x42, 0x0a, 0x07, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x28, 0x2e, 0x63, 0x6e, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x6d, 0x6f, 0x74, 0x6f,
	0x72, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x50,
	0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x52, 0x07, 0x62, 0x61, 0x63,
	0x6b, 0x65, 0x6e, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x12, 0x0a, 0x04,
	0x70, 0x61, 0x74, 0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68,
	0x12, 0x44, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x18,
	0x0b, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x63, 0x6e, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e,
	0x6d, 0x6f, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43,
	0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x52, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x69, 0x6e, 0x73, 0x65, 0x63, 0x75,
	0x72, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x69, 0x6e, 0x73, 0x65, 0x63, 0x75,
	0x72, 0x65, 0x12, 0x34, 0x0a, 0x04, 0x73, 0x75, 0x64, 0x6f, 0x18, 0x15, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x20, 0x2e, 0x63, 0x6e, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x6d, 0x6f, 0x74, 0x6f, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x75,
	0x64, 0x6f, 0x52, 0x04, 0x73, 0x75, 0x64, 0x6f, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x63, 0x6f,
	0x72, 0x64, 0x18, 0x16, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64,
	0x12, 0x49, 0x0a, 0x07, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x17, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x2f, 0x2e, 0x63, 0x6e, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x6d, 0x6f, 0x74, 0x6f,
	0x72, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x07, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x41, 0x0a, 0x08, 0x64,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x18, 0x1b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x25, 0x2e,
	0x63, 0x6e, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x6d, 0x6f, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72,
	0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f,
	0x76, 0x65, 0x72, 0x79, 0x52, 0x08, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x12, 0x34,
	0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x18, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x20, 0x2e, 0x63,
	0x6e, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x6d, 0x6f, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f,
	0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4b, 0x69, 0x6e, 0x64, 0x52, 0x04,
	0x6b, 0x69, 0x6e, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x19, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x1f,
	0x0a, 0x0b, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x5f, 0x69, 0x64, 0x18, 0x1a, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x49, 0x64, 0x1a,
	0x3a, 0x0a, 0x0c, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x4a, 0x04, 0x08, 0x06, 0x10,
	0x07, 0x4a, 0x04, 0x08, 0x07, 0x10, 0x08, 0x4a, 0x04, 0x08, 0x09, 0x10, 0x0a, 0x4a, 0x04, 0x08,
	0x0a, 0x10, 0x0b, 0x4a, 0x04, 0x08, 0x14, 0x10, 0x15, 0x22, 0x48, 0x0a, 0x04, 0x53, 0x75, 0x64,
	0x6f, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x06, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x73, 0x65,
	0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x14, 0x0a,
	0x05, 0x73, 0x68, 0x65, 0x6c, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x73, 0x68,
	0x65, 0x6c, 0x6c, 0x22, 0xab, 0x01, 0x0a, 0x09, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72,
	0x79, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x07, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x73, 0x12, 0x49, 0x0a, 0x06, 0x66,
	0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x63, 0x6e,
	0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x6d, 0x6f, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65,
	0x72, 0x79, 0x2e, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06,
	0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x1a, 0x39, 0x0a, 0x0b, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x2a, 0x9a, 0x03, 0x0a, 0x0c, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x54, 0x79,
	0x70, 0x65, 0x12, 0x0c, 0x0a, 0x08, 0x4c, 0x4f, 0x43, 0x41, 0x4c, 0x5f, 0x4f, 0x53, 0x10, 0x00,
	0x12, 0x17, 0x0a, 0x13, 0x44, 0x4f, 0x43, 0x4b, 0x45, 0x52, 0x5f, 0x45, 0x4e, 0x47, 0x49, 0x4e,
	0x45, 0x5f, 0x49, 0x4d, 0x41, 0x47, 0x45, 0x10, 0x01, 0x12, 0x1b, 0x0a, 0x17, 0x44, 0x4f, 0x43,
	0x4b, 0x45, 0x52, 0x5f, 0x45, 0x4e, 0x47, 0x49, 0x4e, 0x45, 0x5f, 0x43, 0x4f, 0x4e, 0x54, 0x41,
	0x49, 0x4e, 0x45, 0x52, 0x10, 0x02, 0x12, 0x07, 0x0a, 0x03, 0x53, 0x53, 0x48, 0x10, 0x03, 0x12,
	0x09, 0x0a, 0x05, 0x57, 0x49, 0x4e, 0x52, 0x4d, 0x10, 0x04, 0x12, 0x17, 0x0a, 0x13, 0x41, 0x57,
	0x53, 0x5f, 0x53, 0x53, 0x4d, 0x5f, 0x52, 0x55, 0x4e, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e,
	0x44, 0x10, 0x05, 0x12, 0x16, 0x0a, 0x12, 0x43, 0x4f, 0x4e, 0x54, 0x41, 0x49, 0x4e, 0x45, 0x52,
	0x5f, 0x52, 0x45, 0x47, 0x49, 0x53, 0x54, 0x52, 0x59, 0x10, 0x06, 0x12, 0x07, 0x0a, 0x03, 0x54,
	0x41, 0x52, 0x10, 0x07, 0x12, 0x08, 0x0a, 0x04, 0x4d, 0x4f, 0x43, 0x4b, 0x10, 0x08, 0x12, 0x0b,
	0x0a, 0x07, 0x56, 0x53, 0x50, 0x48, 0x45, 0x52, 0x45, 0x10, 0x09, 0x12, 0x0d, 0x0a, 0x09, 0x41,
	0x52, 0x49, 0x53, 0x54, 0x41, 0x45, 0x4f, 0x53, 0x10, 0x0a, 0x12, 0x07, 0x0a, 0x03, 0x41, 0x57,
	0x53, 0x10, 0x0c, 0x12, 0x07, 0x0a, 0x03, 0x47, 0x43, 0x50, 0x10, 0x0d, 0x12, 0x09, 0x0a, 0x05,
	0x41, 0x5a, 0x55, 0x52, 0x45, 0x10, 0x0e, 0x12, 0x09, 0x0a, 0x05, 0x4d, 0x53, 0x33, 0x36, 0x35,
	0x10, 0x0f, 0x12, 0x08, 0x0a, 0x04, 0x49, 0x50, 0x4d, 0x49, 0x10, 0x10, 0x12, 0x0e, 0x0a, 0x0a,
	0x56, 0x53, 0x50, 0x48, 0x45, 0x52, 0x45, 0x5f, 0x56, 0x4d, 0x10, 0x11, 0x12, 0x06, 0x0a, 0x02,
	0x46, 0x53, 0x10, 0x12, 0x12, 0x07, 0x0a, 0x03, 0x4b, 0x38, 0x53, 0x10, 0x13, 0x12, 0x11, 0x0a,
	0x0d, 0x45, 0x51, 0x55, 0x49, 0x4e, 0x49, 0x58, 0x5f, 0x4d, 0x45, 0x54, 0x41, 0x4c, 0x10, 0x14,
	0x12, 0x0a, 0x0a, 0x06, 0x44, 0x4f, 0x43, 0x4b, 0x45, 0x52, 0x10, 0x15, 0x12, 0x0a, 0x0a, 0x06,
	0x47, 0x49, 0x54, 0x48, 0x55, 0x42, 0x10, 0x16, 0x12, 0x0b, 0x0a, 0x07, 0x56, 0x41, 0x47, 0x52,
	0x41, 0x4e, 0x54, 0x10, 0x17, 0x12, 0x0f, 0x0a, 0x0b, 0x41, 0x57, 0x53, 0x5f, 0x45, 0x43, 0x32,
	0x5f, 0x45, 0x42, 0x53, 0x10, 0x18, 0x12, 0x0a, 0x0a, 0x06, 0x47, 0x49, 0x54, 0x4c, 0x41, 0x42,
	0x10, 0x19, 0x12, 0x0d, 0x0a, 0x09, 0x54, 0x45, 0x52, 0x52, 0x41, 0x46, 0x4f, 0x52, 0x4d, 0x10,
	0x1a, 0x12, 0x08, 0x0a, 0x04, 0x48, 0x4f, 0x53, 0x54, 0x10, 0x1b, 0x12, 0x0b, 0x0a, 0x07, 0x55,
	0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x1c, 0x22, 0x04, 0x08, 0x0b, 0x10, 0x0b, 0x2a, 0xfd,
	0x01, 0x0a, 0x04, 0x4b, 0x69, 0x6e, 0x64, 0x12, 0x10, 0x0a, 0x0c, 0x4b, 0x49, 0x4e, 0x44, 0x5f,
	0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x1e, 0x0a, 0x1a, 0x4b, 0x49, 0x4e,
	0x44, 0x5f, 0x56, 0x49, 0x52, 0x54, 0x55, 0x41, 0x4c, 0x5f, 0x4d, 0x41, 0x43, 0x48, 0x49, 0x4e,
	0x45, 0x5f, 0x49, 0x4d, 0x41, 0x47, 0x45, 0x10, 0x01, 0x12, 0x18, 0x0a, 0x14, 0x4b, 0x49, 0x4e,
	0x44, 0x5f, 0x43, 0x4f, 0x4e, 0x54, 0x41, 0x49, 0x4e, 0x45, 0x52, 0x5f, 0x49, 0x4d, 0x41, 0x47,
	0x45, 0x10, 0x02, 0x12, 0x0d, 0x0a, 0x09, 0x4b, 0x49, 0x4e, 0x44, 0x5f, 0x43, 0x4f, 0x44, 0x45,
	0x10, 0x03, 0x12, 0x10, 0x0a, 0x0c, 0x4b, 0x49, 0x4e, 0x44, 0x5f, 0x50, 0x41, 0x43, 0x4b, 0x41,
	0x47, 0x45, 0x10, 0x04, 0x12, 0x18, 0x0a, 0x14, 0x4b, 0x49, 0x4e, 0x44, 0x5f, 0x56, 0x49, 0x52,
	0x54, 0x55, 0x41, 0x4c, 0x5f, 0x4d, 0x41, 0x43, 0x48, 0x49, 0x4e, 0x45, 0x10, 0x05, 0x12, 0x12,
	0x0a, 0x0e, 0x4b, 0x49, 0x4e, 0x44, 0x5f, 0x43, 0x4f, 0x4e, 0x54, 0x41, 0x49, 0x4e, 0x45, 0x52,
	0x10, 0x06, 0x12, 0x10, 0x0a, 0x0c, 0x4b, 0x49, 0x4e, 0x44, 0x5f, 0x50, 0x52, 0x4f, 0x43, 0x45,
	0x53, 0x53, 0x10, 0x07, 0x12, 0x0c, 0x0a, 0x08, 0x4b, 0x49, 0x4e, 0x44, 0x5f, 0x41, 0x50, 0x49,
	0x10, 0x08, 0x12, 0x13, 0x0a, 0x0f, 0x4b, 0x49, 0x4e, 0x44, 0x5f, 0x42, 0x41, 0x52, 0x45, 0x5f,
	0x4d, 0x45, 0x54, 0x41, 0x4c, 0x10, 0x09, 0x12, 0x10, 0x0a, 0x0c, 0x4b, 0x49, 0x4e, 0x44, 0x5f,
	0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x10, 0x0a, 0x12, 0x13, 0x0a, 0x0f, 0x4b, 0x49, 0x4e,
	0x44, 0x5f, 0x4b, 0x38, 0x53, 0x5f, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54, 0x10, 0x0b, 0x42, 0x27,
	0x5a, 0x25, 0x67, 0x6f, 0x2e, 0x6d, 0x6f, 0x6e, 0x64, 0x6f, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x63, 0x6e, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2f, 0x6d, 0x6f, 0x74, 0x6f, 0x72, 0x2f, 0x70, 0x72,
	0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_provider_proto_rawDescOnce sync.Once
	file_provider_proto_rawDescData = file_provider_proto_rawDesc
)

func file_provider_proto_rawDescGZIP() []byte {
	file_provider_proto_rawDescOnce.Do(func() {
		file_provider_proto_rawDescData = protoimpl.X.CompressGZIP(file_provider_proto_rawDescData)
	})
	return file_provider_proto_rawDescData
}

var file_provider_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_provider_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_provider_proto_goTypes = []interface{}{
	(ProviderType)(0),        // 0: cnquery.motor.providers.v1.ProviderType
	(Kind)(0),                // 1: cnquery.motor.providers.v1.Kind
	(*Config)(nil),           // 2: cnquery.motor.providers.v1.Config
	(*Sudo)(nil),             // 3: cnquery.motor.providers.v1.Sudo
	(*Discovery)(nil),        // 4: cnquery.motor.providers.v1.Discovery
	nil,                      // 5: cnquery.motor.providers.v1.Config.OptionsEntry
	nil,                      // 6: cnquery.motor.providers.v1.Discovery.FilterEntry
	(*vault.Credential)(nil), // 7: cnquery.motor.vault.v1.Credential
}
var file_provider_proto_depIdxs = []int32{
	0, // 0: cnquery.motor.providers.v1.Config.backend:type_name -> cnquery.motor.providers.v1.ProviderType
	7, // 1: cnquery.motor.providers.v1.Config.credentials:type_name -> cnquery.motor.vault.v1.Credential
	3, // 2: cnquery.motor.providers.v1.Config.sudo:type_name -> cnquery.motor.providers.v1.Sudo
	5, // 3: cnquery.motor.providers.v1.Config.options:type_name -> cnquery.motor.providers.v1.Config.OptionsEntry
	4, // 4: cnquery.motor.providers.v1.Config.discover:type_name -> cnquery.motor.providers.v1.Discovery
	1, // 5: cnquery.motor.providers.v1.Config.kind:type_name -> cnquery.motor.providers.v1.Kind
	6, // 6: cnquery.motor.providers.v1.Discovery.filter:type_name -> cnquery.motor.providers.v1.Discovery.FilterEntry
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_provider_proto_init() }
func file_provider_proto_init() {
	if File_provider_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_provider_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_provider_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Sudo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_provider_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Discovery); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_provider_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_provider_proto_goTypes,
		DependencyIndexes: file_provider_proto_depIdxs,
		EnumInfos:         file_provider_proto_enumTypes,
		MessageInfos:      file_provider_proto_msgTypes,
	}.Build()
	File_provider_proto = out.File
	file_provider_proto_rawDesc = nil
	file_provider_proto_goTypes = nil
	file_provider_proto_depIdxs = nil
}
