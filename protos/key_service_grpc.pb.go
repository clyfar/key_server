// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.21.12
// source: protos/key_service.proto

package protos

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	KeyService_CreateKey_FullMethodName         = "/key_service.KeyService/CreateKey"
	KeyService_DeleteKey_FullMethodName         = "/key_service.KeyService/DeleteKey"
	KeyService_SearchKeys_FullMethodName        = "/key_service.KeyService/SearchKeys"
	KeyService_FetchKeyByUUID_FullMethodName    = "/key_service.KeyService/FetchKeyByUUID"
	KeyService_FetchKeyByID_FullMethodName      = "/key_service.KeyService/FetchKeyByID"
	KeyService_FetchAndUnwrapKey_FullMethodName = "/key_service.KeyService/FetchAndUnwrapKey"
)

// KeyServiceClient is the client API for KeyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type KeyServiceClient interface {
	CreateKey(ctx context.Context, in *CreateKeyRequest, opts ...grpc.CallOption) (*CreateKeyResponse, error)
	DeleteKey(ctx context.Context, in *DeleteKeyRequest, opts ...grpc.CallOption) (*DeleteKeyResponse, error)
	SearchKeys(ctx context.Context, in *SearchKeysRequest, opts ...grpc.CallOption) (*SearchKeysResponse, error)
	FetchKeyByUUID(ctx context.Context, in *FetchKeyByUUIDRequest, opts ...grpc.CallOption) (*FetchKeyByUUIDResponse, error)
	FetchKeyByID(ctx context.Context, in *FetchKeyByIDRequest, opts ...grpc.CallOption) (*FetchKeyByIDResponse, error)
	FetchAndUnwrapKey(ctx context.Context, in *FetchAndUnwrapKeyRequest, opts ...grpc.CallOption) (*FetchAndUnwrapKeyResponse, error)
}

type keyServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewKeyServiceClient(cc grpc.ClientConnInterface) KeyServiceClient {
	return &keyServiceClient{cc}
}

func (c *keyServiceClient) CreateKey(ctx context.Context, in *CreateKeyRequest, opts ...grpc.CallOption) (*CreateKeyResponse, error) {
	out := new(CreateKeyResponse)
	err := c.cc.Invoke(ctx, KeyService_CreateKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyServiceClient) DeleteKey(ctx context.Context, in *DeleteKeyRequest, opts ...grpc.CallOption) (*DeleteKeyResponse, error) {
	out := new(DeleteKeyResponse)
	err := c.cc.Invoke(ctx, KeyService_DeleteKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyServiceClient) SearchKeys(ctx context.Context, in *SearchKeysRequest, opts ...grpc.CallOption) (*SearchKeysResponse, error) {
	out := new(SearchKeysResponse)
	err := c.cc.Invoke(ctx, KeyService_SearchKeys_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyServiceClient) FetchKeyByUUID(ctx context.Context, in *FetchKeyByUUIDRequest, opts ...grpc.CallOption) (*FetchKeyByUUIDResponse, error) {
	out := new(FetchKeyByUUIDResponse)
	err := c.cc.Invoke(ctx, KeyService_FetchKeyByUUID_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyServiceClient) FetchKeyByID(ctx context.Context, in *FetchKeyByIDRequest, opts ...grpc.CallOption) (*FetchKeyByIDResponse, error) {
	out := new(FetchKeyByIDResponse)
	err := c.cc.Invoke(ctx, KeyService_FetchKeyByID_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyServiceClient) FetchAndUnwrapKey(ctx context.Context, in *FetchAndUnwrapKeyRequest, opts ...grpc.CallOption) (*FetchAndUnwrapKeyResponse, error) {
	out := new(FetchAndUnwrapKeyResponse)
	err := c.cc.Invoke(ctx, KeyService_FetchAndUnwrapKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeyServiceServer is the server API for KeyService service.
// All implementations must embed UnimplementedKeyServiceServer
// for forward compatibility
type KeyServiceServer interface {
	CreateKey(context.Context, *CreateKeyRequest) (*CreateKeyResponse, error)
	DeleteKey(context.Context, *DeleteKeyRequest) (*DeleteKeyResponse, error)
	SearchKeys(context.Context, *SearchKeysRequest) (*SearchKeysResponse, error)
	FetchKeyByUUID(context.Context, *FetchKeyByUUIDRequest) (*FetchKeyByUUIDResponse, error)
	FetchKeyByID(context.Context, *FetchKeyByIDRequest) (*FetchKeyByIDResponse, error)
	FetchAndUnwrapKey(context.Context, *FetchAndUnwrapKeyRequest) (*FetchAndUnwrapKeyResponse, error)
	mustEmbedUnimplementedKeyServiceServer()
}

// UnimplementedKeyServiceServer must be embedded to have forward compatible implementations.
type UnimplementedKeyServiceServer struct {
}

func (UnimplementedKeyServiceServer) CreateKey(context.Context, *CreateKeyRequest) (*CreateKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateKey not implemented")
}
func (UnimplementedKeyServiceServer) DeleteKey(context.Context, *DeleteKeyRequest) (*DeleteKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteKey not implemented")
}
func (UnimplementedKeyServiceServer) SearchKeys(context.Context, *SearchKeysRequest) (*SearchKeysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SearchKeys not implemented")
}
func (UnimplementedKeyServiceServer) FetchKeyByUUID(context.Context, *FetchKeyByUUIDRequest) (*FetchKeyByUUIDResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FetchKeyByUUID not implemented")
}
func (UnimplementedKeyServiceServer) FetchKeyByID(context.Context, *FetchKeyByIDRequest) (*FetchKeyByIDResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FetchKeyByID not implemented")
}
func (UnimplementedKeyServiceServer) FetchAndUnwrapKey(context.Context, *FetchAndUnwrapKeyRequest) (*FetchAndUnwrapKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FetchAndUnwrapKey not implemented")
}
func (UnimplementedKeyServiceServer) mustEmbedUnimplementedKeyServiceServer() {}

// UnsafeKeyServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to KeyServiceServer will
// result in compilation errors.
type UnsafeKeyServiceServer interface {
	mustEmbedUnimplementedKeyServiceServer()
}

func RegisterKeyServiceServer(s grpc.ServiceRegistrar, srv KeyServiceServer) {
	s.RegisterService(&KeyService_ServiceDesc, srv)
}

func _KeyService_CreateKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).CreateKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyService_CreateKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).CreateKey(ctx, req.(*CreateKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyService_DeleteKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).DeleteKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyService_DeleteKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).DeleteKey(ctx, req.(*DeleteKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyService_SearchKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SearchKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).SearchKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyService_SearchKeys_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).SearchKeys(ctx, req.(*SearchKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyService_FetchKeyByUUID_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchKeyByUUIDRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).FetchKeyByUUID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyService_FetchKeyByUUID_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).FetchKeyByUUID(ctx, req.(*FetchKeyByUUIDRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyService_FetchKeyByID_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchKeyByIDRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).FetchKeyByID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyService_FetchKeyByID_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).FetchKeyByID(ctx, req.(*FetchKeyByIDRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyService_FetchAndUnwrapKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchAndUnwrapKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).FetchAndUnwrapKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyService_FetchAndUnwrapKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).FetchAndUnwrapKey(ctx, req.(*FetchAndUnwrapKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// KeyService_ServiceDesc is the grpc.ServiceDesc for KeyService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var KeyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "key_service.KeyService",
	HandlerType: (*KeyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateKey",
			Handler:    _KeyService_CreateKey_Handler,
		},
		{
			MethodName: "DeleteKey",
			Handler:    _KeyService_DeleteKey_Handler,
		},
		{
			MethodName: "SearchKeys",
			Handler:    _KeyService_SearchKeys_Handler,
		},
		{
			MethodName: "FetchKeyByUUID",
			Handler:    _KeyService_FetchKeyByUUID_Handler,
		},
		{
			MethodName: "FetchKeyByID",
			Handler:    _KeyService_FetchKeyByID_Handler,
		},
		{
			MethodName: "FetchAndUnwrapKey",
			Handler:    _KeyService_FetchAndUnwrapKey_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "protos/key_service.proto",
}
