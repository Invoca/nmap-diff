package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/server"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
)

type markdownText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type block struct {
	BlockType string `json:"type"`
	BlockText *markdownText `json:"text,omitempty"`
}

type slackBody struct {
	Blocks []block `json:"blocks"`
}

type Slack struct {
	slackUrl string
}

func SetupSlack(config config.BaseConfig) (*Slack, error) {
	if config.SlackConfig == nil {
		return nil, fmt.Errorf("Error: SlackConfig cannot be nil")
	}

	if config.SlackConfig.SlackURL == "" {
		return nil, fmt.Errorf("Error: SlackURL cannot be empty")
	}

	s := Slack{}
	s.slackUrl = config.SlackConfig.SlackURL
	return &s, nil
}

func (s *Slack) createBlockSlackPost(text string, additionalText string) error {
	var blockSlice []block

	divider :=  block{
		BlockType: "divider",
	}

	mainMarkdown := markdownText{
		Type: "mrkdwn",
		Text: text,
	}

	additionalInfoMarkdown := markdownText{
		Type: "mrkdwn",
		Text: additionalText,
	}

	mainBlock := block{
		BlockType: "section",
		BlockText: &mainMarkdown,
	}

	additionalInfoBlock := block{
		BlockType: "section",
		BlockText: &additionalInfoMarkdown,
	}

	blockSlice = append(blockSlice, divider, mainBlock, additionalInfoBlock)

	body := slackBody{Blocks: blockSlice}

	data, _ := json.Marshal(body)

	log.Debug(string(data))

	resp, err := http.Post(s.slackUrl, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("createBlockSlackPost: Error Posting Request %s", err)
	}

	if resp.Status != "200 OK" {
		return fmt.Errorf("createBlockSlackPost: Received non 200 Status Code %s", err)
	}
	log.Debug("Received Status: " + resp.Status)
	return nil
}

func (s *Slack) formatLabels(labels map[string] string) string {
	baseString := "Labels:\t"
	formatSpacing := "\n\t\t\t\t"
	firstLabel := true
	for name, value := range labels {
		if firstLabel {
			baseString = baseString + name + ": " + value
			firstLabel = false
			continue
		}
		baseString = baseString + formatSpacing + name + ": " + value
	}
	return baseString
}

//TODO: Refactor usage of server struct to be able to use ports field
func (s *Slack) PrintOpenedPorts(host server.Server, ports []uint16) error {
	for _, port := range ports {
		title := ":large_green_circle: *Host* `" + host.Name + "` _Opened_ *Port* `" + strconv.FormatUint(uint64(port), 10) + "`"

		attachmentText := "*Address*: " + host.Address + "\n"
		attachmentText = attachmentText + s.formatLabels(host.Tags)

		err := s.createBlockSlackPost(title, attachmentText)
		if err != nil {
			return fmt.Errorf("PrintOpenedPorts: Error posting message to slack %s", err)
		}
	}
	return nil
}

//TODO: Refactor usage of server struct to be able to use ports field
func (s *Slack) PrintClosedPorts(host server.Server, ports []uint16) error {
	for _, port := range ports {
		text := ":large_red_circle: *Host* `" + host.Name + "` _Closed_ *Port* `" + strconv.FormatUint(uint64(port), 10) + "`"

		attachmentText := "*Address*: " + host.Address + "\n"
		attachmentText = attachmentText + s.formatLabels(host.Tags)
		err := s.createBlockSlackPost(text, attachmentText)
		if err != nil {
			return fmt.Errorf("PrintClosedPorts: Error posting message to slack %s", err)
		}
	}

	return nil
}