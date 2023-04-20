package main

import (
	"context"
	"log"
	"net"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"google.golang.org/grpc"

	pb "github.com/clyfar/key_server/protos"
)

type server struct {
	pb.UnimplementedKeyServiceServer
	kmsClient *kms.KMS
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

	result, err := s.kmsClient.CreateKey(input)
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

	_, err = s.kmsClient.ScheduleKeyDeletion(input)
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

	err := s.kmsClient.ListKeysPages(input, func(page *kms.ListKeysOutput, lastPage bool) bool {
		for _, key := range page.Keys {
			metadataInput := &kms.DescribeKeyInput{KeyId: key.KeyId}
			metadataOutput, err := s.kmsClient.DescribeKey(metadataInput)
			if err != nil {
				continue
			}

			keyMetadata := metadataOutput.KeyMetadata
			keyTagsOutput, err := s.kmsClient.ListResourceTags(&kms.ListResourceTagsInput{KeyId: keyMetadata.KeyId})
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

	kmsClient := kms.New(awsSession)

	pb.RegisterKeyServiceServer(s, &server{kmsClient: kmsClient})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
