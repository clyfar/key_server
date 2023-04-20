// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: protos/key_service.proto

package key_service

import (
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

type CreateKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid        string `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Alias       string `protobuf:"bytes,2,opt,name=alias,proto3" json:"alias,omitempty"`
	Description string `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
}

func (x *CreateKeyRequest) Reset() {
	*x = CreateKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_key_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateKeyRequest) ProtoMessage() {}

func (x *CreateKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_protos_key_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateKeyRequest.ProtoReflect.Descriptor instead.
func (*CreateKeyRequest) Descriptor() ([]byte, []int) {
	return file_protos_key_service_proto_rawDescGZIP(), []int{0}
}

func (x *CreateKeyRequest) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *CreateKeyRequest) GetAlias() string {
	if x != nil {
		return x.Alias
	}
	return ""
}

func (x *CreateKeyRequest) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

type CreateKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
}

func (x *CreateKeyResponse) Reset() {
	*x = CreateKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_key_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateKeyResponse) ProtoMessage() {}

func (x *CreateKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_protos_key_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateKeyResponse.ProtoReflect.Descriptor instead.
func (*CreateKeyResponse) Descriptor() ([]byte, []int) {
	return file_protos_key_service_proto_rawDescGZIP(), []int{1}
}

func (x *CreateKeyResponse) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

type DeleteKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid string `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
}

func (x *DeleteKeyRequest) Reset() {
	*x = DeleteKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_key_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteKeyRequest) ProtoMessage() {}

func (x *DeleteKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_protos_key_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteKeyRequest.ProtoReflect.Descriptor instead.
func (*DeleteKeyRequest) Descriptor() ([]byte, []int) {
	return file_protos_key_service_proto_rawDescGZIP(), []int{2}
}

func (x *DeleteKeyRequest) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

type DeleteKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Success bool `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
}

func (x *DeleteKeyResponse) Reset() {
	*x = DeleteKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_key_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteKeyResponse) ProtoMessage() {}

func (x *DeleteKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_protos_key_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteKeyResponse.ProtoReflect.Descriptor instead.
func (*DeleteKeyResponse) Descriptor() ([]byte, []int) {
	return file_protos_key_service_proto_rawDescGZIP(), []int{3}
}

func (x *DeleteKeyResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

type SearchKeysRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid string `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
}

func (x *SearchKeysRequest) Reset() {
	*x = SearchKeysRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_key_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SearchKeysRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SearchKeysRequest) ProtoMessage() {}

func (x *SearchKeysRequest) ProtoReflect() protoreflect.Message {
	mi := &file_protos_key_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SearchKeysRequest.ProtoReflect.Descriptor instead.
func (*SearchKeysRequest) Descriptor() ([]byte, []int) {
	return file_protos_key_service_proto_rawDescGZIP(), []int{4}
}

func (x *SearchKeysRequest) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

type SearchKeysResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyIds []string `protobuf:"bytes,1,rep,name=key_ids,json=keyIds,proto3" json:"key_ids,omitempty"`
}

func (x *SearchKeysResponse) Reset() {
	*x = SearchKeysResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_key_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SearchKeysResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SearchKeysResponse) ProtoMessage() {}

func (x *SearchKeysResponse) ProtoReflect() protoreflect.Message {
	mi := &file_protos_key_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SearchKeysResponse.ProtoReflect.Descriptor instead.
func (*SearchKeysResponse) Descriptor() ([]byte, []int) {
	return file_protos_key_service_proto_rawDescGZIP(), []int{5}
}

func (x *SearchKeysResponse) GetKeyIds() []string {
	if x != nil {
		return x.KeyIds
	}
	return nil
}

var File_protos_key_service_proto protoreflect.FileDescriptor

var file_protos_key_service_proto_rawDesc = []byte{
	0x0a, 0x18, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x6b, 0x65, 0x79, 0x5f, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x6b, 0x65, 0x79, 0x5f,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22, 0x5e, 0x0a, 0x10, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x75,
	0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x12,
	0x14, 0x0a, 0x05, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x61, 0x6c, 0x69, 0x61, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x2a, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15, 0x0a, 0x06,
	0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b, 0x65,
	0x79, 0x49, 0x64, 0x22, 0x26, 0x0a, 0x10, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4b, 0x65, 0x79,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x22, 0x2d, 0x0a, 0x11, 0x44,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x27, 0x0a, 0x11, 0x53, 0x65,
	0x61, 0x72, 0x63, 0x68, 0x4b, 0x65, 0x79, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75,
	0x75, 0x69, 0x64, 0x22, 0x2d, 0x0a, 0x12, 0x53, 0x65, 0x61, 0x72, 0x63, 0x68, 0x4b, 0x65, 0x79,
	0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x6b, 0x65, 0x79,
	0x5f, 0x69, 0x64, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x6b, 0x65, 0x79, 0x49,
	0x64, 0x73, 0x32, 0xf3, 0x01, 0x0a, 0x0a, 0x4b, 0x65, 0x79, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x12, 0x4a, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x1d,
	0x2e, 0x6b, 0x65, 0x79, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e,
	0x6b, 0x65, 0x79, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4a, 0x0a,
	0x09, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x1d, 0x2e, 0x6b, 0x65, 0x79,
	0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4b,
	0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x6b, 0x65, 0x79, 0x5f,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4b, 0x65,
	0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4d, 0x0a, 0x0a, 0x53, 0x65, 0x61,
	0x72, 0x63, 0x68, 0x4b, 0x65, 0x79, 0x73, 0x12, 0x1e, 0x2e, 0x6b, 0x65, 0x79, 0x5f, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x53, 0x65, 0x61, 0x72, 0x63, 0x68, 0x4b, 0x65, 0x79, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x6b, 0x65, 0x79, 0x5f, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x53, 0x65, 0x61, 0x72, 0x63, 0x68, 0x4b, 0x65, 0x79, 0x73,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x31, 0x5a, 0x2f, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6c, 0x79, 0x66, 0x61, 0x72, 0x2f, 0x6b, 0x65,
	0x79, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f,
	0x6b, 0x65, 0x79, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_protos_key_service_proto_rawDescOnce sync.Once
	file_protos_key_service_proto_rawDescData = file_protos_key_service_proto_rawDesc
)

func file_protos_key_service_proto_rawDescGZIP() []byte {
	file_protos_key_service_proto_rawDescOnce.Do(func() {
		file_protos_key_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_protos_key_service_proto_rawDescData)
	})
	return file_protos_key_service_proto_rawDescData
}

var file_protos_key_service_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_protos_key_service_proto_goTypes = []interface{}{
	(*CreateKeyRequest)(nil),   // 0: key_service.CreateKeyRequest
	(*CreateKeyResponse)(nil),  // 1: key_service.CreateKeyResponse
	(*DeleteKeyRequest)(nil),   // 2: key_service.DeleteKeyRequest
	(*DeleteKeyResponse)(nil),  // 3: key_service.DeleteKeyResponse
	(*SearchKeysRequest)(nil),  // 4: key_service.SearchKeysRequest
	(*SearchKeysResponse)(nil), // 5: key_service.SearchKeysResponse
}
var file_protos_key_service_proto_depIdxs = []int32{
	0, // 0: key_service.KeyService.CreateKey:input_type -> key_service.CreateKeyRequest
	2, // 1: key_service.KeyService.DeleteKey:input_type -> key_service.DeleteKeyRequest
	4, // 2: key_service.KeyService.SearchKeys:input_type -> key_service.SearchKeysRequest
	1, // 3: key_service.KeyService.CreateKey:output_type -> key_service.CreateKeyResponse
	3, // 4: key_service.KeyService.DeleteKey:output_type -> key_service.DeleteKeyResponse
	5, // 5: key_service.KeyService.SearchKeys:output_type -> key_service.SearchKeysResponse
	3, // [3:6] is the sub-list for method output_type
	0, // [0:3] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protos_key_service_proto_init() }
func file_protos_key_service_proto_init() {
	if File_protos_key_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protos_key_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateKeyRequest); i {
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
		file_protos_key_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateKeyResponse); i {
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
		file_protos_key_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteKeyRequest); i {
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
		file_protos_key_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteKeyResponse); i {
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
		file_protos_key_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SearchKeysRequest); i {
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
		file_protos_key_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SearchKeysResponse); i {
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
			RawDescriptor: file_protos_key_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_protos_key_service_proto_goTypes,
		DependencyIndexes: file_protos_key_service_proto_depIdxs,
		MessageInfos:      file_protos_key_service_proto_msgTypes,
	}.Build()
	File_protos_key_service_proto = out.File
	file_protos_key_service_proto_rawDesc = nil
	file_protos_key_service_proto_goTypes = nil
	file_protos_key_service_proto_depIdxs = nil
}
