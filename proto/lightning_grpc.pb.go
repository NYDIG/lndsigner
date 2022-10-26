// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package proto

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

// LightningClient is the client API for Lightning service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type LightningClient interface {
	// lncli: `signmessage`
	//SignMessage signs a message with this node's private key. The returned
	//signature string is `zbase32` encoded and pubkey recoverable, meaning that
	//only the message digest and signature are needed for verification.
	SignMessage(ctx context.Context, in *SignMessageRequest, opts ...grpc.CallOption) (*SignMessageResponse, error)
}

type lightningClient struct {
	cc grpc.ClientConnInterface
}

func NewLightningClient(cc grpc.ClientConnInterface) LightningClient {
	return &lightningClient{cc}
}

func (c *lightningClient) SignMessage(ctx context.Context, in *SignMessageRequest, opts ...grpc.CallOption) (*SignMessageResponse, error) {
	out := new(SignMessageResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/SignMessage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LightningServer is the server API for Lightning service.
// All implementations must embed UnimplementedLightningServer
// for forward compatibility
type LightningServer interface {
	// lncli: `signmessage`
	//SignMessage signs a message with this node's private key. The returned
	//signature string is `zbase32` encoded and pubkey recoverable, meaning that
	//only the message digest and signature are needed for verification.
	SignMessage(context.Context, *SignMessageRequest) (*SignMessageResponse, error)
	mustEmbedUnimplementedLightningServer()
}

// UnimplementedLightningServer must be embedded to have forward compatible implementations.
type UnimplementedLightningServer struct {
}

func (UnimplementedLightningServer) SignMessage(context.Context, *SignMessageRequest) (*SignMessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignMessage not implemented")
}
func (UnimplementedLightningServer) mustEmbedUnimplementedLightningServer() {}

// UnsafeLightningServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to LightningServer will
// result in compilation errors.
type UnsafeLightningServer interface {
	mustEmbedUnimplementedLightningServer()
}

func RegisterLightningServer(s grpc.ServiceRegistrar, srv LightningServer) {
	s.RegisterService(&Lightning_ServiceDesc, srv)
}

func _Lightning_SignMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignMessageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).SignMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/SignMessage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).SignMessage(ctx, req.(*SignMessageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Lightning_ServiceDesc is the grpc.ServiceDesc for Lightning service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Lightning_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.Lightning",
	HandlerType: (*LightningServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignMessage",
			Handler:    _Lightning_SignMessage_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "lightning.proto",
}
