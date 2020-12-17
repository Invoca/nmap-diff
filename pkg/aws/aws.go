package aws

import (
	"bytes"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"io/ioutil"
	"os"
	"math/rand"

	"github.com/Invoca/nmap-diff/pkg/config"
	"github.com/Invoca/nmap-diff/pkg/server"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	log "github.com/sirupsen/logrus"
)

const (
	instanceRunningState = int64(16)
)

type awsSvc struct {
	regions    []string
	bucketName string
	ec2svc     ec2iface.EC2API
	s3svc      s3iface.S3API
	awsSession *session.Session
}

func New(configObject config.BaseConfig) (*awsSvc, error) {
	var err error
	if configObject.BucketName == "" {
		return nil, fmt.Errorf("New: BucketName cannot be nil")
	}

	a := awsSvc{}

	roleArnName := os.Getenv("ROLE_ARN")

	baseSess := session.Must(session.NewSessionWithOptions(session.Options{}))
	a.awsSession = baseSess

	if roleArnName != "" {
		stsSvc := sts.New(baseSess)
		sessionName := fmt.Sprintf("some-session-%d", rand.Int())
		assumedRole, err := stsSvc.AssumeRole(&sts.AssumeRoleInput{
			RoleArn: aws.String(roleArnName),
			RoleSessionName: aws.String(sessionName),
		})

		if err != nil {
			return nil, fmt.Errorf("Error assuming role %s", err)
		}

		assumedSession, err := session.NewSession(&aws.Config{
			Credentials: credentials.NewStaticCredentials(
				*assumedRole.Credentials.AccessKeyId,
				*assumedRole.Credentials.SecretAccessKey,
				*assumedRole.Credentials.SessionToken),
			Region: aws.String(os.Getenv("AWS_REGION")),
		})

		if err != nil {
			return nil, fmt.Errorf("Error getting assumedSession %s", err)
		}

		a.ec2svc = ec2.New(assumedSession, &aws.Config{
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
	} else {
		a.ec2svc = ec2.New(baseSess, &aws.Config{
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
	}

	a.bucketName = configObject.BucketName
	a.s3svc = s3.New(baseSess)

	err = a.getRegions()
	if err != nil {
		return nil, fmt.Errorf("Error Getting regions %s", err)
	}

	return &a, nil
}

func (a *awsSvc) getRegions() error {
	if a.ec2svc == nil {
		return fmt.Errorf("getRegions: ec2svc is not yet initialized")
	}

	resultRegions, err := a.ec2svc.DescribeRegions(nil)
	if err != nil {
		return fmt.Errorf("getRegions: Error Describing regions %s", err)
	}

	for _, region := range resultRegions.Regions {
		a.regions = append(a.regions, *region.RegionName)
	}
	return nil
}

func (a *awsSvc) getInstancesInRegion(ec2Svc ec2iface.EC2API, serversMap map[string]server.Server) error {
	if ec2Svc == nil {
		return fmt.Errorf("getInstancesInRegion: ec2Svc is nil")
	}

	ec2Instances, err := ec2Svc.DescribeInstances(nil)
	if err != nil {
		return fmt.Errorf("Instances: Error Describing Instances %s", err)
	}

	reservations := ec2Instances.Reservations

	for _, res := range reservations {
		log.Debug("Reservation Id", *res.ReservationId, " Num Instances: ", len(res.Instances))
		for _, inst := range res.Instances {
			// Status code 16 is Runnning state
			if *inst.State.Code == instanceRunningState {
				newInstance := server.Server{}
				newInstance.Tags = make(map[string]string)
				newInstance.Address = *inst.PublicIpAddress
				newInstance.Name = *inst.InstanceId
				for _, tag := range inst.Tags {
					newInstance.Tags[*tag.Key] = *tag.Value
				}
				serversMap[newInstance.Address] = newInstance
			}
		}
	}
	return nil
}

func (a *awsSvc) Instances(serversMap map[string]server.Server) error {
	if a.awsSession == nil {
		return fmt.Errorf("Instances: awsSession Cannot be nil")
	}

	for _, region := range a.regions {
		ec2Svc := ec2.New(a.awsSession, aws.NewConfig().WithRegion(region))
		err := a.getInstancesInRegion(ec2Svc, serversMap)
		for k, v := range serversMap {
			serversMap[k] = v
		}
		if err != nil {
			return fmt.Errorf("Error gettings instances in region %s", err)
		}
	}
	return nil
}

func (a *awsSvc) UploadObjectToS3(fileData []byte, s3Key string) error {
	if a.s3svc == nil {
		return fmt.Errorf("UploadObjectToS3: s3svc cannot be nil")
	}

	_, err := a.s3svc.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(a.bucketName),
		Body:   bytes.NewReader(fileData),
		Key:    aws.String(s3Key),
	})

	if err != nil {
		return fmt.Errorf("Error uploading object %s", err)
	}

	return nil
}

func (a *awsSvc) GetFileFromS3(s3Key string) ([]byte, error) {
	if a.s3svc == nil {
		return nil, fmt.Errorf("GetFileFromS3: s3svc cannot be nil")
	}

	resp, err := a.s3svc.GetObject(&s3.GetObjectInput{
		Key:    aws.String(s3Key),
		Bucket: aws.String(a.bucketName),
	})
	if err != nil {
		return nil, fmt.Errorf("GetFileFromS3: Error getting resp from s3")
	}

	byteSlice, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GetFileFromS3: Error reading to byte slice %s", err)
	}

	return byteSlice, nil
}
