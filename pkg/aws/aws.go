package aws

import (
	"bytes"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/server"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
)

type AWSSvc struct {
	IpAddresses []string
	Regions     []string
	ServersMap  map[string]server.Server
	bucketName  string
	Ec2svc      ec2iface.EC2API
	S3svc       s3iface.S3API
	awsSession  *session.Session
}

func (a *AWSSvc) SetupAWS(configObject config.BaseConfig) error {
	if configObject.BucketName == "" {
		return fmt.Errorf("SetupAWS: BucketName cannot be nil")
	}

	a.ServersMap = make(map[string]server.Server)

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	a.awsSession = sess

	a.Ec2svc = ec2.New(sess)

	a.bucketName = configObject.BucketName
	a.S3svc = s3.New(sess)

	err := a.getRegions()
	if err != nil {
		return fmt.Errorf("Error Getting Regions %s", err)
	}

	return nil
}

func (a *AWSSvc) getRegions() error {
	if a.Ec2svc == nil {
		return fmt.Errorf("getRegions: ec2svc is not yet initialized")
	}

	resultRegions, err := a.Ec2svc.DescribeRegions(nil)
	if err != nil {
		return fmt.Errorf("getRegions: Error Describing Regions %s", err)
	}

	for _, region := range resultRegions.Regions {
		a.Regions = append(a.Regions, *region.RegionName)
	}
	return nil
}

func (a *AWSSvc) getInstancesInRegion(ec2Svc ec2iface.EC2API) error {
	if ec2Svc == nil {
		return fmt.Errorf("getInstancesInRegion: ec2Svc is nil")
	}

	ec2Instances, err := ec2Svc.DescribeInstances(nil)
	if err != nil {
		return fmt.Errorf("GetInstances: Error Describing Instances %s", err)
	}

	reservations := ec2Instances.Reservations

	for idx, res := range reservations {
		log.Debug("Reservation Id", *res.ReservationId, " Num Instances: ", len(res.Instances))
		for _, inst := range reservations[idx].Instances {
			// Status code 16 is Runnning state
			if *inst.State.Code == 16 {
				newInstance := server.Server{}
				newInstance.Tags = make(map[string]string)
				newInstance.Address = *inst.PublicIpAddress
				newInstance.Name = *inst.InstanceId
				for _, tag := range inst.Tags {
					newInstance.Tags[*tag.Key] = *tag.Value
				}
				a.IpAddresses = append(a.IpAddresses, newInstance.Address)
				a.ServersMap[newInstance.Address] = newInstance
			}
		}
	}
	return nil
}

func (a *AWSSvc) GetInstances() error {
	if a.awsSession == nil {
		return fmt.Errorf("GetInstances: awsSession Cannot be nil")
	}

	for _, region := range a.Regions {
		ec2Svc := ec2.New(a.awsSession, aws.NewConfig().WithRegion(region))
		err := a.getInstancesInRegion(ec2Svc)
		if err != nil {
			return fmt.Errorf("Error gettings instances in region %s", err)
		}
	}
	return nil
}

func (a *AWSSvc) UploadObjectToS3(fileData []byte, s3Key string) error {
	if a.S3svc == nil {
		return fmt.Errorf("UploadObjectToS3: S3svc cannot be nil")
	}

	_, err := a.S3svc.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(a.bucketName),
		Body:   bytes.NewReader(fileData),
		Key:    aws.String(s3Key),
	})

	if err != nil {
		return fmt.Errorf("Error uploading object %s", err)
	}

	return nil
}

func (a *AWSSvc) GetFileFromS3(s3Key string) (*[]byte, error) {
	if a.S3svc == nil {
		return nil, fmt.Errorf("GetFileFromS3: S3svc cannot be nil")
	}

	resp, err := a.S3svc.GetObject(&s3.GetObjectInput{
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

	return &byteSlice, nil
}
