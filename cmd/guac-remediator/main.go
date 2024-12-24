package guacremediator

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/robert-cronin/guac-remediator/internal/aggregator"
	"github.com/robert-cronin/guac-remediator/internal/store"
)

// TODO: add cli logic

func main() {
	// initialize aggregator
	// initialize remediator
	// run poll cycle and trigger remediation
	ctx := context.Background()

	httpClient := http.Client{Transport: http.DefaultTransport}
	gqlclient := graphql.NewClient("http://localhost:8080/query", &httpClient)

	pkgInput, err := helpers.PurlToPkg("pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1")
	if err != nil {
		slog.Error("failed to parse PURL: %v", err)
		os.Exit(1)
	}
	pkgFilter := &model.PkgSpec{
		Type:      &pkgInput.Type,
		Namespace: pkgInput.Namespace,
		Name:      &pkgInput.Name,
		Version:   pkgInput.Version,
		Subpath:   pkgInput.Subpath,
	}
	pkgResponse, err := model.Packages(ctx, gqlclient, *pkgFilter)
	if err != nil {
		slog.Error("failed to query packages: %v", err)
		os.Exit(1)
	}
	if len(pkgResponse.Packages) == 0 {
		slog.Error("no packages found")
		os.Exit(1)
	}

	// TODO: add actual remediation logic

	// mock graphql endpoint (replace with your real guac graphql endpoint)
	endpoint := "http://localhost:8080/query"

	// initialize store
	mockStore := &store.MockStore{}

	// initialize aggregator
	agg := aggregator.NewGraphQLAggregator(endpoint, mockStore)

	// poll guac
	vulns, err := agg.Poll()
	if err != nil {
		fmt.Println("error polling guac:", err)
		return
	}
	fmt.Printf("discovered %d vulnerabilities\n", len(vulns))

	fmt.Println("guac-remediator poc running...")
}
