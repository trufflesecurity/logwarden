package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/trufflesecurity/logwarden/internal/result"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type Slack struct {
	WebhookURL string
}

func (o Slack) Send(ctx context.Context, res result.Result) error {
	type slackMessage struct {
		Text string `json:"text"`
	}

	var details string
	for k, v := range res.Details {
		if k == "link" {
			v = fmt.Sprintf("<%s|stackdriver>", v)
		}
		details += fmt.Sprintf("*%s*: %v\n", cases.Title(language.AmericanEnglish).String(k), v)
	}

	body, err := json.Marshal(slackMessage{
		Text: fmt.Sprintf(`*Rule*: %s
*Message*: %s
*Type*: %s
%s`, res.Rule, res.Message, res.Type, details),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.WebhookURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("invalid Slack webhook configuration")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		// A webhook URL contains credentials; never include it in output error logs.
		return fmt.Errorf("Slack webhook request failed (%T)", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status code %d", resp.StatusCode)
	}
	return nil
}
