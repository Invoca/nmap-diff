package wrapper

import "github.com/port-scanner/pkg/server"

type AwsInterface interface {
	GetInstances() (map[string]server.Server, error)
	UploadObjectToS3(fileData []byte, s3Key string) error
	GetFileFromS3(s3Key string) ([]byte, error)
}
