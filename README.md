# nmap-diff

## How It Works
nmap-diff works by pulling the previous run from an S3 bucket as a starting point. The previous run is the xml output of an nmap scan. nmap-diff then starts a new scan and a diff is made between the current run and the previous run. Only newly closed and opened ports will be posted to Slack. After posting to Slack, the current nmap scan result will be uploaded to S3 replacing the previous one.

## Setup
There are two ways to run the nmap server as an http server and from the command line. The http server requires the AWS 
Both methods requires AWS credentials in order to fetch and save the scan. 


## Running The Scan 

### Server
Running the nmap-diff as an http server is as simple as running this command.

```
docker run quay.io/invoca/nmap-diff:server
```

To trigger a scan with the webserver, create a http post request in the following format. Note that the port can be changed by setting the `$PORT` environment variable. 

```
curl -X POST -k --data '{"bucketName": "$BUCKETNAME", "previousFileName": "$FILENAME", "slackURL": "$SLACK_URL", "includeGCloud": $BOOL, "includeAWS": $BOOL,"projectName": "$PROJECTNAME"}' $HOSTNAME:8080
```


### Command

To trigger a nmap run from the commandline image, add arguments to the docker run command. 

```
docker run quay.io/invoca/nmap-diff:cmd ./nmap-diff --gcloud-project $PROJECTNAME --s3-bucket $BUCKETNAME -u $SLACK_URL --report-path=$REPORT_PATH --include-aws=$BOOL --include-gcloud=$BOOL
```


## Contributions

Contributions to this project are always welcome!  Please read our [Contribution Guidelines](https://github.com/Invoca/nmap-diff/blob/master/CONTRIBUTING.md) before starting any work.
