package aggregator

import (
	"context"
	"fmt"
	"time"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/robert-cronin/guac-remediator/internal/event"
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
	eventBus     *event.EventBus
}

// NewGUACAggregatorPoller creates a GUACAggregator with a default interval of 5m unless specified.
func NewGUACAggregatorPoller(client graphql.Client, s store.Store, interval time.Duration, bus *event.EventBus) *GUACAggregator {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &GUACAggregator{
		client:       client,
		store:        s,
		pollInterval: interval,
		stopCh:       make(chan struct{}),
		seenIDs:      make(map[string]bool),
		eventBus:     bus,
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
	var afterId *string
	pageSize := 20

	for {
		filter := buildCertifyVulnFilter()
		resp, err := model.CertifyVulnList(ctx, g.client, filter, afterId, &pageSize)
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

			// Skip if we've seen this node ID already.
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
			err := g.store.SaveVulnerabilityRecords(ctx, newRecords)
			if err != nil {
				return err
			}
			// Publish an event for newly discovered vulnerabilities
			g.eventBus.Publish(ctx, event.Event{
				Type: event.VulnDiscovered,
				Data: map[string]interface{}{
					"records": newRecords,
				},
			})
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

// buildCertifyVulnFilter returns a simple CertifyVulnSpec that retrieves all vulnerabilities.
func buildCertifyVulnFilter() model.CertifyVulnSpec {
	// For this POC, we return everything. Custom filters could be added if needed.
	return model.CertifyVulnSpec{}
}

// ========================================================================================

// findTopLevelOCIForPkg queries guac to identify the top-level container purl
// for a given pkg
func findTopLevelOCIPurl(ctx context.Context, gqlclient graphql.Client, vulnID string) (string, error) {
	filter := model.IsDependencySpec{}

	resp, err := model.Dependencies(ctx, gqlclient, filter)
	if err != nil {
		return "", err
	}

	dependencies := resp.GetIsDependency()
	// there should only be one top-level package
	if len(dependencies) != 1 {
		return "", fmt.Errorf("expected 1 top-level package, got %d", len(dependencies))
	}

	// see if there is an oci package
	var ociIsDependency *model.DependenciesIsDependency
	for _, dep := range dependencies {
		pkg := dep.GetPackage()
		if pkg.Type != "oci" {
			ociIsDependency = &dep
			break
		}
	}

	if ociIsDependency == nil {
		return "", fmt.Errorf("expected at least one oci package, got 0")
	}

	purl := helpers.AllPkgTreeToPurl(&ociIsDependency.Package.AllPkgTree)

	return purl, nil
}
