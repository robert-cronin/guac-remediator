// cmd/guac-remediator/cli/root.go
package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/robert-cronin/guac-remediator/internal/aggregator"
	"github.com/robert-cronin/guac-remediator/internal/event"
	"github.com/robert-cronin/guac-remediator/internal/remediator"
	"github.com/robert-cronin/guac-remediator/internal/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "guac-remediator",
	Short: "A proof-of-concept system for polling GUAC and orchestrating remediation tasks.",
	Long: `guac-remediator polls the guac graphql endpoint for vulnerabilities
and orchestrates remediation workflows (e.g., via COPA).`,
	Run: func(cmd *cobra.Command, args []string) {
		runRoot(cmd, args)
	},
}

func init() {
	// define flags
	rootCmd.PersistentFlags().String("guac-endpoint", "http://localhost:8080/query", "the guac graphql endpoint")
	rootCmd.PersistentFlags().Duration("poll-interval", 5*time.Minute, "interval for polling guac for vulnerabilities")

	// bind flags to viper
	_ = viper.BindPFlag("guac_endpoint", rootCmd.PersistentFlags().Lookup("guac-endpoint"))
	_ = viper.BindPFlag("poll_interval", rootCmd.PersistentFlags().Lookup("poll-interval"))

	// set prefix or read env automatically
	// e.g. REM_GUAC_ENDPOINT, REM_POLL_INTERVAL
	viper.SetEnvPrefix("REM")
	viper.AutomaticEnv()
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runRoot(cmd *cobra.Command, args []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// watch for ctrl+c or kill signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// read config from flags/env
	guacEndpoint := viper.GetString("guac_endpoint")
	pollInterval := viper.GetDuration("poll_interval")

	// create a graphql client
	gqlclient := graphql.NewClient(guacEndpoint, http.DefaultClient)

	// create store
	mockStore := store.NewMockStore()

	// create event bus
    bus := event.NewEventBus()
	
	// create aggregator poller
	agg := aggregator.NewGUACAggregatorPoller(gqlclient, mockStore, pollInterval, bus)

	// create basic a remediator
	basicRem := remediator.NewBasicRemediator()
	if err := basicRem.Initialize(); err != nil {
		fmt.Println("failed to init basicRemediator:", err)
		return
	}

	// create the remediation manager
	remManager := remediator.NewRemediationManager(basicRem, bus)

	// create and subscribe orchestrator
	orch := remediator.NewOrchestrator(remManager)
	bus.Subscribe(orch)

	fmt.Printf("starting guac-remediator aggregator poller...\n")
	fmt.Printf("guac_endpoint: %s\n", guacEndpoint)
	fmt.Printf("poll_interval: %s\n", pollInterval)

	// start aggregator
	go agg.Start(ctx)

	// wait for signal
	select {
	case <-sigCh:
		fmt.Println("shutting down aggregator poller...")
		agg.Stop()
		time.Sleep(2 * time.Second) // grace period
		fmt.Println("exiting")
	}
}
