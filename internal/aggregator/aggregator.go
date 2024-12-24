package aggregator

import (
	"context"
	"fmt"
	"time"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/robert-cronin/guac-remediator/internal/store"
)

// Aggregator is the interface for polling vulnerabilities.
type Aggregator interface {
	Start(ctx context.Context)
	Stop()
}

// GUACAggregator periodically queries guac, paginating CertifyVulnList results.
type GUACAggregator struct {
	client       graphql.Client
	store        store.Store
	pollInterval time.Duration
	stopCh       chan struct{}
	seenIDs      map[string]bool
}

// NewGUACAggregatorPoller creates a GUACAggregator with a default interval of 5m unless specified.
func NewGUACAggregatorPoller(client graphql.Client, s store.Store, interval time.Duration) *GUACAggregator {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &GUACAggregator{
		client:       client,
		store:        s,
		pollInterval: interval,
		stopCh:       make(chan struct{}),
		seenIDs:      make(map[string]bool),
	}
}

// Start begins polling in a background goroutine.
func (g *GUACAggregator) Start(ctx context.Context) {
	err := g.pollOnce(ctx)
	if err != nil {
		fmt.Println("poll error:", err)
	}

	ticker := time.NewTicker(g.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := g.pollOnce(ctx)
			if err != nil {
				fmt.Println("poll error:", err)
			}
		case <-g.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// Stop signals the poller to stop.
func (g *GUACAggregator) Stop() {
	close(g.stopCh)
}

// pollOnce runs a single poll cycle, fetching pages until exhausted.
func (g *GUACAggregator) pollOnce(ctx context.Context) error {
	var afterId *string = nil
	pageSize := 20

	for {
		resp, err := model.CertifyVulnList(ctx, g.client, buildCertifyVulnFilter(), afterId, &pageSize)
		if err != nil {
			return err
		}

		list := resp.GetCertifyVulnList()
		if list == nil || len(list.Edges) == 0 {
			break
		}

		// process each edge
		var newRecords []store.VulnerabilityRecord
		for _, edge := range list.Edges {
			node := edge.GetNode()

			// skip if we've seen it
			if g.seenIDs[node.Id] {
				continue
			}
			g.seenIDs[node.Id] = true

			vr := store.VulnerabilityRecord{
				ID:          node.Id,
				CertifyVuln: node.AllCertifyVuln,
			}
			newRecords = append(newRecords, vr)
		}

		// store newly discovered
		if len(newRecords) > 0 {
			err := g.store.SaveVulnerabilityRecords(newRecords)
			if err != nil {
				return err
			}
		}

		// move afterId
		if list.PageInfo.HasNextPage && list.PageInfo.EndCursor != nil {
			afterId = list.PageInfo.EndCursor
		} else {
			break
		}
	}

	return nil
}

// buildCertifyVulnFilter returns a simple CertifyVulnSpec
func buildCertifyVulnFilter() model.CertifyVulnSpec {
	// mockFilter := model.CertifyVulnSpec{
	// 	Id: utils.Ptr(""),
	// 	Package: &model.PkgSpec{
	// 		Id:        utils.Ptr(""),
	// 		Type:      utils.Ptr(""),
	// 		Namespace: utils.Ptr(""),
	// 		Name:      utils.Ptr(""),
	// 		Version:   utils.Ptr(""),
	// 	},
	// 	Vulnerability: &model.VulnerabilitySpec{
	// 		Id:              utils.Ptr(""),
	// 		Type:            utils.Ptr(""),
	// 		VulnerabilityID: utils.Ptr(""),
	// 		NoVuln:          utils.Ptr(false),
	// 	},
	// 	Origin:    utils.Ptr(""),
	// 	Collector: utils.Ptr(""),
	// }

	return model.CertifyVulnSpec{}
}
