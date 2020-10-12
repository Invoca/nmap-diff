package main

import (
	"encoding/json"
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/runner"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

type Config struct {
	IncludeAWS bool `json:"includeAWS"`
	BucketName  string `json:"bucketName"`
	PreviousFileName string `json:"previousFileName"`
	IncludeGCloud bool `json:"includeGCloud"`
	ServiceAccountPath string `json:"serviceAccountPath"`
	SlackURL string `json:"slackURL"`
	ProjectName string `json:"projectName"`
}

func main() {
	log.SetLevel(log.DebugLevel)

	log.Debug("starting server...")
	http.HandleFunc("/", scanHandler)

	// Determine port for HTTP service.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Debug("defaulting to port ", port)
	}

	// Start HTTP server.
	log.Printf("listening on port ", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	var c Config

	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		log.WithField("error", err).Error("Error Decoding Body")
		http.Error(w, "Error Decoding Body: " + err.Error(), 500)
		w.WriteHeader(500)
	}

	log.Debug(c)

	gCloudConfig := config.GCloudConfig {
		ServiceAccountPath: c.ServiceAccountPath,
		ProjectName: c.ProjectName,
	}

	slackConfig := config.SlackConfig {
		SlackURL: c.SlackURL,
	}

	configObject := config.BaseConfig {
		IncludeAWS:       c.IncludeAWS,
		BucketName:       c.BucketName,
		PreviousFileName: c.PreviousFileName,
		IncludeGCloud:    c.IncludeGCloud,
		GCloudConfig:     &gCloudConfig,
		SlackConfig:      &slackConfig,
	}

	err = runner.Execute(configObject)
	if err != nil {
		log.WithField("error", err).Error("Error Executing runner")
		http.Error(w, "Error Executing runner: " + err.Error(), 500)
		w.WriteHeader(500)
	}
}