package runner

import (
	"fmt"
	"github.com/port-scanner/pkg/aws"
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/gcloud"
	"github.com/port-scanner/pkg/scanner"
	"github.com/port-scanner/pkg/server"
	"github.com/port-scanner/pkg/slack"
	"github.com/port-scanner/pkg/wrapper"
	log "github.com/sirupsen/logrus"
	"strconv"
)

type runner struct {
	awsSvc    wrapper.AwsSvc
	gCloudSvc wrapper.GCloudSvc
	slackSvc  wrapper.SlackSvc
	nmapSvc   wrapper.NmapSvc
}

func Execute(configObject config.BaseConfig) error {
	r, err := setupRunner(configObject)
	if err != nil {
		return fmt.Errorf("Execute: Error setting up Runner %s", err)
	}
	err = r.run(configObject)
	if err != nil {
		return fmt.Errorf("Execute: Error on run %s", err)
	}
	return nil
}

func setupRunner(configObject config.BaseConfig) (*runner, error) {
	var err error

	r := &runner{}
	log.Debug("Configuring AWS package")

	r.awsSvc, err = aws.SetupAWS(configObject)
	if err != nil {
		return nil, fmt.Errorf("setupRunner: error configuring AWS %s", err)
	}

	log.Debug("Configuring slack package")
	r.slackSvc, err = slack.SetupSlack(configObject)
	if err != nil {
		return nil, fmt.Errorf("setupRunner: Unable to create slack Interface %s", err)
	}

	log.Debug("Configuring gcloud package")
	r.gCloudSvc, err = gcloud.Setup(configObject)
	if err != nil {
		return nil, fmt.Errorf("setupRunner: error Setting up gCloud interface %s", err)
	}

	log.Debug("Setting up Nmap package")
	r.nmapSvc, err = scanner.SetupNmap()
	if err != nil {
		return nil, fmt.Errorf("setupRunner: Error setting up nmapStruct interface: %s", err)
	}

	return r, nil
}

func (r *runner) run(configObject config.BaseConfig) error {

	log.Debug("Fetching Instances From AWS")
	serversMap := make(map[string]server.Server)
	err := r.awsSvc.Instances(serversMap)
	if err != nil {
		return fmt.Errorf("Run: Unable to run get AWS Instances: %s", err)
	}

	log.Debug("Fetching Instances From GCloud")
	err = r.gCloudSvc.Instances(serversMap)
	if err != nil {
		return fmt.Errorf("Run: Unable to run get Google Cloud Instances: %s", err)
	}

	log.Debug("Parsing servers map to slice")
	ipAddresses := make([]string, len(serversMap))
	i := 0
	for k, _ := range serversMap {
		ipAddresses[i] = k
		i += 1
	}

	log.Debug("Fetching previous scan from S3")
	scanBytes, err := r.awsSvc.GetFileFromS3(configObject.PreviousFileName)
	if err != nil {
		return fmt.Errorf("Run: Error getting object %s", err)
	}

	log.Debug("Parsing results of previous scan")
	oldInstances, err := r.nmapSvc.ParsePreviousScan(scanBytes)
	if err != nil {
		return fmt.Errorf("Run: Unable to parse previous results in scanner %s", err)
	}

	log.Debug("Starting Scan With " + strconv.FormatInt(int64(len(ipAddresses)), 10) + " Instances")
	newInstances, err := r.nmapSvc.StartScan(ipAddresses)
	if err != nil {
		return fmt.Errorf("Run: Unable to run nmap scan: %s", err)
	}

	log.Debug("Analyzing the result of current scan and previous scan")
	instancesExposed, instancesRemoved, err := r.nmapSvc.DiffScans(newInstances, oldInstances)
	if err != nil {
		return fmt.Errorf("Run: Error Diffing Scans %s", err)
	}

	currentScanSlice, err := r.nmapSvc.CurrentScanResults()
	if err != nil {
		return fmt.Errorf("Run: Error Retrieving Current Scan")
	}

	log.Debug("Uploading current scan to S3")
	err = r.awsSvc.UploadObjectToS3(currentScanSlice, configObject.PreviousFileName)
	if err != nil {
		return fmt.Errorf("Run: Unable to upload object to S3 %s", err)
	}

	log.Debug("Printing opened ports")
	for host, portsMap := range instancesExposed {
		if len(portsMap) == 0 {
			continue
		}

		//TODO: Refactor to remove the map to slice conversion.
		portsSlice := make([]uint16, 0)
		for port, _ := range portsMap {
			if port != 0 {
				portsSlice = append(portsSlice, port)
			}
		}

		err = r.slackSvc.PrintOpenedPorts(serversMap[host], portsSlice)
		if err != nil {
			return fmt.Errorf("Run: Error posting to slack %s", err)
		}
	}

	log.Debug("Printing closed ports")
	for host, portsMap := range instancesRemoved {
		if len(portsMap) == 0 {
			continue
		}

		//TODO: Refactor to remove the map to slice conversion.
		portsSlice := make([]uint16, 0)
		for port, _ := range portsMap {
			if port != 0 {
				portsSlice = append(portsSlice, port)
			}
		}

		err = r.slackSvc.PrintClosedPorts(serversMap[host], portsSlice)
		if err != nil {
			return fmt.Errorf("Run: Error posting to slack %s", err)
		}
	}
	return nil
}
