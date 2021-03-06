package wrapper

import "github.com/Invoca/nmap-diff/pkg/server"

type AwsSvc interface {
	Instances(map[string]server.Server) error
	UploadObjectToS3(fileData []byte, s3Key string) error
	GetFileFromS3(s3Key string) ([]byte, error)
}
