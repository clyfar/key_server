package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	//"encoding/base64"
	//"fmt"
	"testing"
	//"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/clyfar/key_server/mocks/mock_kmsiface"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	//mock_kmsiface "github.com/clyfar/key_server/mocks/mock_kmsiface"
	pb "github.com/clyfar/key_server/protos"
)

type testServer struct {
	*server
}

func (s *testServer) wrapKeyMaterial(keyMaterial []byte, publicKeyBytes []byte, importToken []byte) ([]byte, error) {
	return []byte("fake-wrapped-key-material"), nil
}

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

func TestFetchKeyByUUID(t *testing.T) {
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

	mockKMS.EXPECT().GetPublicKey(gomock.Any()).Return(&kms.GetPublicKeyOutput{PublicKey: []byte("fake-key-material")}, nil)

	req := &pb.FetchKeyByUUIDRequest{
		Uuid: "test-uuid",
	}

	resp, err := s.FetchKeyByUUID(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "fake-key-material", resp.KeyMaterial)
}

func TestCreateAndStoreKeyInKMS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKMS := mock_kmsiface.NewMockKMSAPI(ctrl)
	s := &server{
		KmsClient: mockKMS,
	}

	createKeyOutput := &kms.CreateKeyOutput{
		KeyMetadata: &kms.KeyMetadata{
			KeyId: aws.String("test-key-id"),
		},
	}

	mockKMS.EXPECT().ImportKeyMaterial(gomock.Any()).Return(&kms.ImportKeyMaterialOutput{}, nil)

	mockKMS.EXPECT().CreateKey(gomock.Any()).Return(createKeyOutput, nil)

	importToken := make([]byte, 128) // A 128-byte long import token
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}

	mockKMS.EXPECT().GetParametersForImport(gomock.Any()).Return(&kms.GetParametersForImportOutput{
		ImportToken: importToken,
		PublicKey:   publicKeyBytes,
	}, nil)

	req := &pb.CreateAndStoreKeyInKMSRequest{
		Uuid:        "test-uuid",
		Alias:       "test-alias",
		Description: "test-description",
	}

	resp, err := s.CreateAndStoreKeyInKMS(context.Background(), req)

	if err != nil {
		t.Errorf("Failed to store 128-bit key in KMS: %v", err)
	}

	if resp.GetKeyId() != "test-key-id" {
		t.Errorf("Expected key ID 'test-key-id', got '%s'", resp.GetKeyId())
	}
}

func createKeyAndImportMaterial(t *testing.T, s *server) ([]byte, []byte, []byte, []byte, error) {
	req := &pb.CreateAndStoreKeyInKMSRequest{
		Uuid: "test-uuid",
	}

	_, err := s.CreateAndStoreKeyInKMS(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to create and store key in KMS: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Convert rsaKey to PKCS1 format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}

	keyMaterial := []byte("fake-128-bit-key")
	importToken := make([]byte, 128)
	if _, err := rand.Read(importToken); err != nil {
		t.Fatalf("failed to generate import token: %v", err)
	}

	return publicKeyBytes, privateKeyBytes, keyMaterial, importToken, nil
}

func TestWrapAndUnwrapKeyMaterial(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}

	s := &server{}

	keyMaterial := []byte("fake-128-bit-key")
	importToken := make([]byte, 128)
	if _, err := rand.Read(importToken); err != nil {
		t.Fatalf("failed to generate random import token: %v", err)
	}

	wrappedKey, err := s.wrapKeyMaterial(keyMaterial, publicKeyBytes, importToken)
	if err != nil {
		t.Fatalf("failed to wrap key material: %v", err)
	}

	unwrappedKey, err := s.unwrapKeyMaterial(wrappedKey, rsaKey, importToken)
	if err != nil {
		t.Fatalf("failed to unwrap key material: %v", err)
	}

	if !bytes.Equal(keyMaterial, unwrappedKey) {
		t.Errorf("unwrapped key material does not match original key material: got %v, want %v", unwrappedKey, keyMaterial)
	}
}

func setupMockForFindKeyByUUID(mockKMS *mock_kmsiface.MockKMSAPI, keyID, uuid string) {
	mockKMS.EXPECT().ListKeysPages(gomock.Any(), gomock.Any()).DoAndReturn(
		func(input *kms.ListKeysInput, fn func(page *kms.ListKeysOutput, lastPage bool) bool) error {
			fn(&kms.ListKeysOutput{
				Keys: []*kms.KeyListEntry{
					{
						KeyId: aws.String(keyID),
					},
				},
			}, true)
			return nil
		}).Times(1)

	mockKMS.EXPECT().DescribeKey(gomock.Any()).Return(&kms.DescribeKeyOutput{
		KeyMetadata: &kms.KeyMetadata{
			KeyId: aws.String(keyID),
		},
	}, nil).Times(1)

	mockKMS.EXPECT().ListResourceTags(gomock.Any()).Return(&kms.ListResourceTagsOutput{
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("uuid"),
				TagValue: aws.String(uuid),
			},
		},
	}, nil).Times(1)
}

func TestFindKeyByUUID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKMS := mock_kmsiface.NewMockKMSAPI(ctrl)
	s := &server{KmsClient: mockKMS}

	keyID := "test-key-id"
	uuid := "test-uuid"
	setupMockForFindKeyByUUID(mockKMS, keyID, uuid)

	foundKeyID, err := s.findKeyByUUID(uuid)
	if err != nil {
		t.Fatalf("findKeyByUUID returned an error: %v", err)
	}

	if foundKeyID != keyID {
		t.Fatalf("findKeyByUUID returned incorrect key ID, expected %s, got %s", keyID, foundKeyID)
	}
}
