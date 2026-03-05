package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	describe := flag.String("describe", "", "describe an SObject (e.g. -describe Account)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  soquery <SOQL>              run a SOQL query\n")
		fmt.Fprintf(os.Stderr, "  soquery -describe <SObject> describe an SObject\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *describe == "" && flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	client := mustConnect()

	if *describe != "" {
		fields, err := client.Describe(*describe)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := FormatMarkdown(os.Stdout, fields); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	soql := flag.Arg(0)
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

func mustConnect() *Client {
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

	return NewClient(instanceURL, accessToken)
}
