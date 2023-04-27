package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	//"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"google.golang.org/grpc"

	pb "github.com/clyfar/key_server/protos"
)

type server struct {
	pb.UnimplementedKeyServiceServer
	KmsClient kmsiface.KMSAPI
	//kmsClient *kms.KMS
}

func (s *server) CreateKey(ctx context.Context, req *pb.CreateKeyRequest) (*pb.CreateKeyResponse, error) {
	input := &kms.CreateKeyInput{
		Description: aws.String(req.Description),
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("alias"),
				TagValue: aws.String(req.Alias),
			},
			{
				TagKey:   aws.String("uuid"),
				TagValue: aws.String(req.Uuid),
			},
		},
	}

	result, err := s.KmsClient.CreateKey(input)
	if err != nil {
		return nil, err
	}

	return &pb.CreateKeyResponse{
		KeyId: aws.StringValue(result.KeyMetadata.KeyId),
	}, nil
}

func (s *server) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	keyId, err := s.findKeyByUUID(req.Uuid)
	if err != nil {
		return nil, err
	}

	input := &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(keyId),
		PendingWindowInDays: aws.Int64(7),
	}

	_, err = s.KmsClient.ScheduleKeyDeletion(input)
	if err != nil {
		return nil, err
	}

	return &pb.DeleteKeyResponse{Success: true}, nil
}

func (s *server) SearchKeys(ctx context.Context, req *pb.SearchKeysRequest) (*pb.SearchKeysResponse, error) {
	keyId, err := s.findKeyByUUID(req.Uuid)
	if err != nil {
		return nil, err
	}

	return &pb.SearchKeysResponse{
		KeyIds: []string{keyId},
	}, nil
}

func (s *server) findKeyByUUID(uuid string) (string, error) {
	input := &kms.ListKeysInput{}
	var keyId string

	err := s.KmsClient.ListKeysPages(input, func(page *kms.ListKeysOutput, lastPage bool) bool {
		for _, key := range page.Keys {
			metadataInput := &kms.DescribeKeyInput{KeyId: key.KeyId}
			metadataOutput, err := s.KmsClient.DescribeKey(metadataInput)
			if err != nil {
				continue
			}

			keyMetadata := metadataOutput.KeyMetadata
			keyTagsOutput, err := s.KmsClient.ListResourceTags(&kms.ListResourceTagsInput{KeyId: keyMetadata.KeyId})
			if err != nil {
				continue
			}

			for _, tag := range keyTagsOutput.Tags {
				if aws.StringValue(tag.TagKey) == "uuid" && aws.StringValue(tag.TagValue) == uuid {
					keyId = aws.StringValue(keyMetadata.KeyId)
					return false
				}
			}
		}
		return !lastPage
	})

	if err != nil {
		return "", err
	}

	if keyId == "" {
		return "", fmt.Errorf("key not found with UUID: %s", uuid)
	}

	return keyId, nil
}

func (s *server) FetchKeyByID(ctx context.Context, in *pb.FetchKeyByIDRequest) (*pb.FetchKeyByIDResponse, error) {
	keyID := in.GetKeyId()
	// Use the AWS KMS client to fetch the key material by ID.
	// Assuming that the key material is a plaintext string.
	keyMaterial, err := fetchKeyMaterialFromKMS(s.KmsClient, keyID)
	if err != nil {
		return nil, err
	}

	return &pb.FetchKeyByIDResponse{KeyMaterial: keyMaterial}, nil
}

func (s *server) FetchKeyByUUID(ctx context.Context, in *pb.FetchKeyByUUIDRequest) (*pb.FetchKeyByUUIDResponse, error) {
	uuid := in.GetUuid()
	keyID, err := s.findKeyByUUID(uuid)
	if err != nil {
		return nil, err
	}

	fetchKeyByIDReq := &pb.FetchKeyByIDRequest{KeyId: keyID}
	fetchKeyByIDResp, err := s.FetchKeyByID(ctx, fetchKeyByIDReq)
	if err != nil {
		return nil, err
	}

	return &pb.FetchKeyByUUIDResponse{KeyMaterial: fetchKeyByIDResp.GetKeyMaterial()}, nil
}

func fetchKeyMaterialFromKMS(kmsClient kmsiface.KMSAPI, keyID string) (string, error) {
	// Replace this with the actual AWS KMS code to fetch the key material.
	// This is just an example.
	output, err := kmsClient.GetPublicKey(&kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return "", err
	}

	// Assuming that the key material is a plaintext string.
	keyMaterial := string(output.PublicKey)
	return keyMaterial, nil
}

func (s *server) generate128BitKey() ([]byte, error) {
	key := make([]byte, 16) // 16 bytes * 8 bits/byte = 128 bits
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (s *server) wrapKeyMaterial(keyMaterial []byte, publicKeyBytes []byte, importToken []byte) ([]byte, error) {
	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an RSA key")
	}

	// Generate a label for the OAEP padding, which is the SHA-256 hash of the import token
	label := sha256.Sum256(importToken)

	// Encrypt the key material using RSA-OAEP with SHA-256
	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, keyMaterial, label[:])
	if err != nil {
		return nil, err
	}

	return wrappedKey, nil
}

func (s *server) unwrapKeyMaterial(wrappedKey []byte, privateKey *rsa.PrivateKey, importToken []byte) ([]byte, error) {
	// Generate a label for the OAEP padding, which is the SHA-256 hash of the import token
	label := sha256.Sum256(importToken)

	// Decrypt the key material using RSA-OAEP with SHA-256
	unwrappedKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, wrappedKey, label[:])
	if err != nil {
		return nil, err
	}

	return unwrappedKey, nil
}

func (s *server) fetchAndUnwrapKey(ctx context.Context, keyUUID string, privateKey *rsa.PrivateKey, importToken []byte) ([]byte, error) {
	// Call FetchKeyByUUID
	fetchKeyByUUIDReq := &pb.FetchKeyByUUIDRequest{Uuid: keyUUID}
	fetchKeyByUUIDResp, err := s.FetchKeyByUUID(ctx, fetchKeyByUUIDReq)
	if err != nil {
		return nil, err
	}

	encryptedKeyMaterial := []byte(fetchKeyByUUIDResp.GetKeyMaterial())
	// Decrypt the encrypted key material
	keyMaterial, err := s.unwrapKeyMaterial(encryptedKeyMaterial, privateKey, importToken)
	if err != nil {
		return nil, err
	}

	return keyMaterial, nil
}

func (s *server) FetchAndUnwrapKey(ctx context.Context, req *pb.FetchAndUnwrapKeyRequest) (*pb.FetchAndUnwrapKeyResponse, error) {
	// Parse the wrapped private key
	privateKey, err := x509.ParsePKCS1PrivateKey(req.RsaPrivateKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to parse private key")
	}
	fmt.Print(privateKey)
	if privateKey == nil {
		return nil, status.Error(codes.InvalidArgument, "Invalid wrapped private key")
	}

	// Decode the import token
	importToken, err := base64.StdEncoding.DecodeString(req.ImportToken)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Invalid import token")
	}

	// Call the internal fetchAndUnwrapKey method
	keyMaterial, err := s.fetchAndUnwrapKey(ctx, req.Uuid, privateKey, importToken)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to fetch and unwrap key")
	}

	return &pb.FetchAndUnwrapKeyResponse{
		KeyMaterial: base64.StdEncoding.EncodeToString(keyMaterial),
	}, nil
}

func (s *server) CreateAndStoreKeyInKMS(ctx context.Context, req *pb.CreateAndStoreKeyInKMSRequest) (*pb.CreateAndStoreKeyInKMSResponse, error) {
	// Create an empty KMS key
	createKeyInput := &kms.CreateKeyInput{
		Description: aws.String(req.Description),
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("alias"),
				TagValue: aws.String(req.Alias),
			},
			{
				TagKey:   aws.String("uuid"),
				TagValue: aws.String(req.Uuid),
			},
		},
	}
	createKeyOutput, err := s.KmsClient.CreateKey(createKeyInput)
	if err != nil {
		return nil, err
	}
	keyId := aws.StringValue(createKeyOutput.KeyMetadata.KeyId)

	// Generate a 128-bit key
	key, err := s.generate128BitKey()
	if err != nil {
		return nil, err
	}

	// Get parameters for import
	getParamsInput := &kms.GetParametersForImportInput{
		KeyId:             aws.String(keyId),
		WrappingAlgorithm: aws.String("RSAES_OAEP_SHA_256"), // Use a supported wrapping algorithm
		WrappingKeySpec:   aws.String("RSA_2048"),           // Use a supported wrapping key spec
	}
	getParamsOutput, err := s.KmsClient.GetParametersForImport(getParamsInput)
	if err != nil {
		return nil, err
	}

	// Wrap the key material
	wrappedKey, err := s.wrapKeyMaterial(key, getParamsOutput.PublicKey, getParamsOutput.ImportToken)
	if err != nil {
		return nil, err
	}

	// Import the wrapped key material into the KMS key
	importKeyMaterialInput := kms.ImportKeyMaterialInput{
		KeyId:                aws.String(keyId),
		ImportToken:          getParamsOutput.ImportToken,
		EncryptedKeyMaterial: wrappedKey,
		ExpirationModel:      aws.String("KEY_MATERIAL_EXPIRES"),
	}
	_, err = s.KmsClient.ImportKeyMaterial(&importKeyMaterialInput)
	if err != nil {
		return nil, err
	}

	return &pb.CreateAndStoreKeyInKMSResponse{
		KeyId: keyId,
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", "localhost:50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	awsSession, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2"),
	})
	if err != nil {
		log.Fatalf("failed to create AWS session: %v", err)
	}

	KmsClient := kms.New(awsSession)

	pb.RegisterKeyServiceServer(s, &server{KmsClient: KmsClient})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
