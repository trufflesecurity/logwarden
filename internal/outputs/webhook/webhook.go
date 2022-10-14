package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/trufflesecurity/gcp-auditor/internal/result"
)

type Webhook struct {
	PostURL string
}

func (o Webhook) Send(ctx context.Context, res result.Result) error {

	body, err := json.Marshal(res)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", o.PostURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Second * 10}
	_, err = client.Do(req)
	if err != nil {
		return err
	}

	return nil
}
