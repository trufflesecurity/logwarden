package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
)

// GCS generation preconditions make claims exclusive across replicas/restarts.
// Objects contain only status/times; the alert identity appears only as a hash.
type GCS struct{ Bucket *storage.BucketHandle }

func (g GCS) Read(ctx context.Context, key string) (State, int64, error) {
	reader, err := g.Bucket.Object("notifications/v1/" + key + ".json").NewReader(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return State{}, 0, nil
	}
	if err != nil {
		return State{}, 0, err
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil {
		return State{}, 0, err
	}
	if len(data) > 4096 {
		return State{}, 0, errors.New("notification state too large")
	}
	var state State
	err = json.Unmarshal(data, &state)
	return state, reader.Attrs.Generation, err
}
func (g GCS) Write(ctx context.Context, key string, generation int64, state State) (int64, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return 0, err
	}
	condition := storage.Conditions{DoesNotExist: true}
	if generation != 0 {
		condition = storage.Conditions{GenerationMatch: generation}
	}
	writer := g.Bucket.Object("notifications/v1/" + key + ".json").If(condition).NewWriter(ctx)
	writer.ContentType = "application/json"
	writer.ChunkSize = 0
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return 0, err
	}
	if err := writer.Close(); err != nil {
		var api *googleapi.Error
		if errors.As(err, &api) && api.Code == 412 {
			return 0, ErrConflict
		}
		return 0, err
	}
	return writer.Attrs().Generation, nil
}
