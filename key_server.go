package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"

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

func (s *server) CreateAndStoreKeyInKMS(ctx context.Context, req *pb.CreateAndStoreKeyInKMSRequest) (*pb.CreateAndStoreKeyInKMSResponse, error) {
	// Create an empty KMS key
	key, err := s.generate128BitKey()
	if err != nil {
		return nil, err
	}
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

	// Import the 128-bit key material into the KMS key
	expirationModel := "KEY_MATERIAL_EXPIRES"
	importKeyMaterialInput := kms.ImportKeyMaterialInput{
		KeyId:                aws.String(keyId),
		ImportToken:          []byte{}, // Replace with a valid import token
		EncryptedKeyMaterial: key,      // The 128-bit key you generated
		ExpirationModel:      aws.String(expirationModel),
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
