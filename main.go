package main

import (
    "fmt"
    "github.com/port-scanner/pkg/aws"
    "github.com/port-scanner/pkg/config"
    "github.com/port-scanner/pkg/gcloud"
    "github.com/port-scanner/pkg/scanner"
    "github.com/port-scanner/pkg/server"
    "github.com/port-scanner/pkg/slack"
    log "github.com/sirupsen/logrus"
    "os"
)

func main() {
    var ipAddresses []string
    log.SetLevel(log.DebugLevel)

    //TODO: Implement Cobra to populate configObject
    configObject := config.BaseConfig{
        IncludeAWS:    true,
        BucketName:    os.Getenv("S3_BUCKET"),
        PreviousFileName: os.Getenv("FILE_KEY"),
        IncludeGCloud: true,
        GCloudConfig: &config.GCloudConfig{
            ServiceAccountPath: "",
            ProjectName: os.Getenv("GCLOUD_REGION"),
        },
        SlackConfig: &config.SlackConfig{
            SlackURL: os.Getenv("SLACK_URL"),
        },
    }

    serversMap := make(map[string] server.Server)


    awsSvc := aws.AWSSvc{}
    err := awsSvc.SetupAWS(configObject)
    if err != nil {
        fmt.Errorf("Error configuring AWS %s", err)
    }

    err = awsSvc.GetInstances()
    if err != nil {
        fmt.Errorf("unable to run get AWS Instances: %s", err)
    }

    gCloudSvc := gcloud.GCloud{ServersMap: map[string]server.Server{}, IpAddresses: []string{}}
    err = gCloudSvc.Setup(configObject)
    if err != nil {
        fmt.Errorf("Error Setting up gCloud interface %s", err)
    }

    err = gCloudSvc.Instances()
    if err != nil {
        fmt.Errorf("unable to run get Google Cloud Instances: %s", err)
    }

    ipAddresses = append(gCloudSvc.IpAddresses, ipAddresses...)
    for k, v := range gCloudSvc.ServersMap {
        serversMap[k] = v
    }

    nmapScanner, err := scanner.SetupNmap(ipAddresses)
    if err != nil {
        fmt.Errorf("Error setting up Nmap interface: %s", err)
    }

    scanBytes, err := awsSvc.GetFileFromS3(configObject.PreviousFileName)
    if err != nil {
        fmt.Errorf("Error getting object %s", err)
    }

    err = nmapScanner.ParsePreviousScan(*scanBytes)
    if err != nil {
        fmt.Errorf("unable to parse previous results in scanner")
    }

    err = nmapScanner.SetupScan()
    if err != nil {
        fmt.Errorf("Unable to setup nmap scanner")
    }

    err = nmapScanner.StartScan()
    if err != nil {
        fmt.Errorf("unable to run nmap scan: %s", err)
    }

    nmapScanner.DiffScans()

    err = awsSvc.UploadObjectToS3(nmapScanner.CurrentScan, configObject.PreviousFileName)
    if err != nil {
        fmt.Errorf("Unable to upload object to S3")
    }

    slackSvc, err := slack.SetupSlack(configObject)
    if err != nil {
        fmt.Errorf("Unable to create Slack Interface %s", err)
    }

    for host, portsMap := range nmapScanner.NewExposed {
        if len(portsMap) == 0 {
            continue
        }

        //TODO: Refactor to remove the map to slice conversion.
        portsSlice := make([]uint16, len(portsMap))
        for port, _ := range portsMap {
            portsSlice = append(portsSlice, port)
        }

        err = slackSvc.PrintOpenedPorts(serversMap[host], portsSlice)
        if err != nil {
            fmt.Errorf("Error posting to slack %s", err)
        }
    }

    for host, portsMap := range nmapScanner.RemovedExposed {
        if len(portsMap) == 0 {
            continue
        }

        //TODO: Refactor to remove the map to slice conversion.
        portsSlice := make([]uint16, len(portsMap))
        for port, _ := range portsMap {
            portsSlice = append(portsSlice, port)
        }


        err = slackSvc.PrintClosedPorts(serversMap[host], portsSlice)
        if err != nil {
            fmt.Errorf("Error posting to slack %s", err)
        }
    }
}

