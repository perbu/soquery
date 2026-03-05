package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load() // silently ignore if .env is missing

	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: soquery <SOQL statement>")
		fmt.Fprintln(os.Stderr, "Example: soquery \"SELECT Id, Name FROM Account LIMIT 10\"")
		os.Exit(1)
	}
	soql := os.Args[1]

	domain := os.Getenv("SALESFORCE_DOMAIN")
	if domain == "" {
		fmt.Fprintln(os.Stderr, "Error: SALESFORCE_DOMAIN must be set")
		os.Exit(1)
	}
	instanceURL := "https://" + domain

	clientID := os.Getenv("SALESFORCE_CONSUMER_KEY")
	clientSecret := os.Getenv("SALESFORCE_CONSUMER_SECRET")
	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "Error: SALESFORCE_CONSUMER_KEY and SALESFORCE_CONSUMER_SECRET must be set")
		os.Exit(1)
	}

	accessToken, err := ClientCredentialsToken(instanceURL, clientID, clientSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error obtaining token: %v\n", err)
		os.Exit(1)
	}

	client := NewClient(instanceURL, accessToken)
	records, err := client.Query(soql)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := FormatMarkdown(os.Stdout, records); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
