package main

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	pb "key_service"
	mock_kmsiface "key_service/mocks/mock_kmsiface"
)

func TestCreateKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKMS := mock_kmsiface.NewMockKMSAPI(ctrl)
	s := server{kmsClient: mockKMS}

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
	s := server{kmsClient: mockKMS}

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

	resp, err := s
	DeleteKey(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, true, resp.Success)
}

func TestSearchKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKMS := mock_kmsiface.NewMockKMSAPI(ctrl)
	s := server{kmsClient: mockKMS}

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
