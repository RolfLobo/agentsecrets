package main

import (
	"fmt"
	"os"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

func main() {
	client := api.NewClient(func() string {
		return config.GetAccessToken()
	})
	wsSvc := workspaces.NewService(client)
	domains, err := wsSvc.ListAllowlist("e6ff8934-8fb7-46b9-8899-02682b666d2a")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Count: %d\n", len(domains))
	for _, d := range domains {
		fmt.Printf("- %s (added by %s)\n", d.Domain, d.AddedBy)
	}
}
