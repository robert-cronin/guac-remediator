package aggregator

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/robert-cronin/guac-remediator/internal/store"
)

// aggregator
type Aggregator interface {
	Poll() ([]store.VulnerabilityRecord, error)
}

// graphqlaggregator
type GraphQLAggregator struct {
	endpoint string
	store    store.Store
	client   *http.Client
}

// newgraphqlaggregator
func NewGraphQLAggregator(endpoint string, s store.Store) *GraphQLAggregator {
	return &GraphQLAggregator{
		endpoint: endpoint,
		store:    s,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// poll
func (g *GraphQLAggregator) Poll() ([]store.VulnerabilityRecord, error) {
	// build minimal graphql query
	query := `
        query {
          vulnerabilities {
            id
            severity
            title
            purl
          }
        }
    `
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", g.endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// define a small struct to unmarshal data
	var result struct {
		Data struct {
			Vulnerabilities []store.VulnerabilityRecord `json:"vulnerabilities"`
		} `json:"data"`
	}

	err = json.Unmarshal(payload, &result)
	if err != nil {
		return nil, err
	}

	// optionally store them
	now := time.Now().Unix()
	for i := range result.Data.Vulnerabilities {
		result.Data.Vulnerabilities[i].DiscoveredAt = now
	}
	err = g.store.SaveVulnerabilityRecords(result.Data.Vulnerabilities)
	if err != nil {
		return nil, err
	}

	return result.Data.Vulnerabilities, nil
}
