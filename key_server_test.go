package main

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/clyfar/key_server/mocks/mock_kmsiface"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	//mock_kmsiface "github.com/clyfar/key_server/mocks/mock_kmsiface"
	pb "github.com/clyfar/key_server/protos"
)

func TestCreateKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKMS := mock_kmsiface.NewMockKMSAPI(ctrl)
	s := server{KmsClient: mockKMS}

	mockKMS.EXPECT().CreateKey(gomock.Any()).DoAndReturn(func(input *kms.CreateKeyInput) (*kms.CreateKeyOutput, error) {
		assert.NotNil(t, input.Description)
		assert.NotNil(t, input.Tags)
		assert.Equal(t, 2, len(input.Tags))

		return &kms.CreateKeyOutput{
			KeyMetadata: &kms.KeyMetadata{
				KeyId: aws.String("test-key-id"),
			},
		}, nil
	})

	req := &pb.CreateKeyRequest{
		Uuid:        "test-uuid",
		Alias:       "test-alias",
		Description: "test-description",
	}

	resp, err := s.CreateKey(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-key-id", resp.KeyId)
}

func TestDeleteKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKMS := mock_kmsiface.NewMockKMSAPI(ctrl)
	s := server{KmsClient: mockKMS}

	mockKMS.EXPECT().ListKeysPages(gomock.Any(), gomock.Any()).DoAndReturn(func(input *kms.ListKeysInput, fn func(*kms.ListKeysOutput, bool) bool) error {
		fn(&kms.ListKeysOutput{Keys: []*kms.KeyListEntry{
			{KeyId: aws.String("test-key-id")},
		}}, true)
		return nil
	})

	mockKMS.EXPECT().DescribeKey(gomock.Any()).Return(&kms.DescribeKeyOutput{KeyMetadata: &kms.KeyMetadata{KeyId: aws.String("test-key-id")}}, nil)

	mockKMS.EXPECT().ListResourceTags(gomock.Any()).Return(&kms.ListResourceTagsOutput{
		Tags: []*kms.Tag{
			{TagKey: aws.String("uuid"), TagValue: aws.String("test-uuid")},
		},
	}, nil)

	mockKMS.EXPECT().ScheduleKeyDeletion(gomock.Any()).DoAndReturn(func(input *kms.ScheduleKeyDeletionInput) (*kms.ScheduleKeyDeletionOutput, error) {
		assert.NotNil(t, input.KeyId)
		assert.Equal(t, "test-key-id", *input.KeyId)

		return &kms.ScheduleKeyDeletionOutput{}, nil
	})

	req := &pb.DeleteKeyRequest{
		Uuid: "test-uuid",
	}

	var resp *pb.DeleteKeyResponse
	resp, err := s.DeleteKey(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, true, resp.Success)
}

func TestSearchKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKMS := mock_kmsiface.NewMockKMSAPI(ctrl)
	s := server{KmsClient: mockKMS}

	mockKMS.EXPECT().ListKeysPages(gomock.Any(), gomock.Any()).DoAndReturn(func(input *kms.ListKeysInput, fn func(*kms.ListKeysOutput, bool) bool) error {
		fn(&kms.ListKeysOutput{Keys: []*kms.KeyListEntry{
			{KeyId: aws.String("test-key-id")},
		}}, true)
		return nil
	})

	mockKMS.EXPECT().DescribeKey(gomock.Any()).Return(&kms.DescribeKeyOutput{KeyMetadata: &kms.KeyMetadata{KeyId: aws.String("test-key-id")}}, nil)

	mockKMS.EXPECT().ListResourceTags(gomock.Any()).Return(&kms.ListResourceTagsOutput{
		Tags: []*kms.Tag{
			{TagKey: aws.String("uuid"), TagValue: aws.String("test-uuid")},
		},
	}, nil)

	req := &pb.SearchKeysRequest{
		Uuid: "test-uuid",
	}

	resp, err := s.SearchKeys(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 1, len(resp.KeyIds))
	assert.Equal(t, "test-key-id", resp.KeyIds[0])
}

func TestFetchKeyByID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKMS := mock_kmsiface.NewMockKMSAPI(ctrl)
	s := server{KmsClient: mockKMS}

	// Replace this with the actual AWS KMS code to fetch the key material.
	// This is just an example.
	keyID := "test-key-id"
	keyMaterial := "fake-key-material"

	req := &pb.FetchKeyByIDRequest{
		KeyId: keyID,
	}

	// Expect the `GetPublicKey` function to be called with the specified key ID.
	mockKMS.EXPECT().GetPublicKey(gomock.Any()).DoAndReturn(func(input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
		assert.NotNil(t, input.KeyId)
		assert.Equal(t, keyID, *input.KeyId)
		return &kms.GetPublicKeyOutput{PublicKey: []byte(keyMaterial)}, nil
	})

	resp, err := s.FetchKeyByID(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, keyMaterial, resp.KeyMaterial)
}
