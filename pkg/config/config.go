package config

type BaseConfig struct {
	IncludeAWS    	 bool
	BucketName 	  	 string
	PreviousFileName string
	IncludeGCloud 	 bool
	HighSeverity  	 bool
	GCloudConfig  	 *GCloudConfig
	SlackConfig   	 *SlackConfig
}

type GCloudConfig struct {
	ServiceAccountPath string
	ProjectName        string
}

type SlackConfig struct {
	SlackURL string
}
