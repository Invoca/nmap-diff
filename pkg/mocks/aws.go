package mocks

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/port-scanner/pkg/server"
)

type MockAWSWrapper struct {
	ResettableMock
}

type MockEC2API struct {
	ec2iface.EC2API
	ResettableMock
}

type MockS3API struct {
	s3iface.S3API
	ResettableMock
}

func (m *MockEC2API) DescribeInstances(input *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
	fmt.Println("DescribeInstances Mock")
	args := m.Called(input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).(*ec2.DescribeInstancesOutput), args.Error(1)
	}
}

func (m *MockEC2API) DescribeRegions(input *ec2.DescribeRegionsInput) (*ec2.DescribeRegionsOutput, error) {
	fmt.Println("DescribeRegionsInput Mock")
	args := m.Called(input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).(*ec2.DescribeRegionsOutput), args.Error(1)
	}
}

func (m *MockS3API) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	fmt.Println("DescribeRegionsInput Mock")
	args := m.Called(input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).(*s3.PutObjectOutput), args.Error(1)
	}
}

func (m *MockS3API) GetObject(input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	fmt.Println("DescribeRegionsInput Mock")
	args := m.Called(input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).(*s3.GetObjectOutput), args.Error(1)
	}
}

func (m *MockAWSWrapper) GetInstances() (map[string]server.Server, error) {
	args := m.Called(nil)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).(map[string]server.Server), args.Error(1)
	}
}

func (m *MockAWSWrapper) UploadObjectToS3(fileData []byte, s3Key string) error {
	args := m.Called(nil)
	if args.Get(0) == nil {
		return args.Error(0)
	} else {
		return args.Error(0)
	}
}

func (m *MockAWSWrapper) GetFileFromS3(s3Key string) ([]byte, error) {
	args := m.Called(nil)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).([]byte), args.Error(0)
	}
}
