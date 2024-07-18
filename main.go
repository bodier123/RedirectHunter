package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	payloadsFile string
	concurrency  int
	keyword      string
	timeout      int
	outputFile   string
	verbose      bool
	ignoreSSL    bool
)

type Result struct {
	OriginalURL  string
	FuzzedURL    string
	RedirectChain []string
	StatusCode    int
	IsVulnerable  bool
}

func init() {
	flag.StringVar(&payloadsFile, "p", "", "File containing payloads")
	flag.IntVar(&concurrency, "c", 20, "Number of concurrent goroutines")
	flag.StringVar(&keyword, "k", "FUZZ", "Keyword to replace in URLs")
	flag.IntVar(&timeout, "t", 10, "Timeout for each request in seconds")
	flag.StringVar(&outputFile, "o", "", "Output file for vulnerable URLs")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&ignoreSSL, "ignore-ssl", false, "Ignore SSL certificate errors")
	flag.Parse()
}

func loadPayloads(filename string) ([]string, error) {
	if filename == "" {
		return nil, fmt.Errorf("payloads file not specified")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		payloads = append(payloads, scanner.Text())
	}
	return payloads, scanner.Err()
}

func fuzzURL(originalURL, payload string) string {
	return strings.Replace(originalURL, keyword, url.QueryEscape(payload), -1)
}

func checkRedirect(client *http.Client, originalURL, fuzzedURL string) Result {
	resp, err := client.Get(fuzzedURL)
	result := Result{OriginalURL: originalURL, FuzzedURL: fuzzedURL}
	
	if err != nil {
		if verbose {
			color.Red("[ERROR] %s: %v", fuzzedURL, err)
		}
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.RedirectChain = []string{originalURL}

	for resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		result.RedirectChain = append(result.RedirectChain, location)
		
		// Check if redirect leads to a different domain
		originalHost := getHost(originalURL)
		redirectHost := getHost(location)
		if originalHost != redirectHost {
			result.IsVulnerable = true
			break
		}

		// Follow the redirect
		resp, err = client.Get(location)
		if err != nil {
			break
		}
	}

	return result
}

func getHost(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func worker(jobs <-chan string, results chan<- Result, wg *sync.WaitGroup, client *http.Client, payloads []string) {
	defer wg.Done()
	for originalURL := range jobs {
		for _, payload := range payloads {
			fuzzedURL := fuzzURL(originalURL, payload)
			result := checkRedirect(client, originalURL, fuzzedURL)
			results <- result
		}
	}
}

func main() {
	payloads, err := loadPayloads(payloadsFile)
	if err != nil {
		color.Red("Error loading payloads: %v", err)
		os.Exit(1)
	}

	color.Cyan(`
   ____         ____                  ____          __ _       __  __
  / __ \____   / __ \___  ____  ___  / __ \___  ___/ /(_)____ / /_/ /
 / / / / __ \ / /_/ / _ \/ __ \/ _ \/ /_/ / _ \/ _  // // __// __/ / 
/ /_/ / /_/ // _, _/  __/ / / /  __/ _, _/  __/ /_/ // // /__/ /_/_/  
\____/ .___//_/ |_|\___/_/ /_/\___/_/ |_|\___/\__,_//_/ \___/\__(_)   
    /_/                                                               
`)

	color.Yellow("Loading URLs from stdin...")
	scanner := bufio.NewScanner(os.Stdin)
	var urls []string
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		color.Red("Error reading URLs: %v", err)
		os.Exit(1)
	}

	color.Yellow("Starting to process %d URLs with %d payloads...", len(urls), len(payloads))

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: ignoreSSL},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	jobs := make(chan string, len(urls))
	results := make(chan Result, len(urls)*len(payloads))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg, client, payloads)
	}

	for _, url := range urls {
		jobs <- url
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var vulnerableURLs []Result
	for result := range results {
		if result.IsVulnerable {
			vulnerableURLs = append(vulnerableURLs, result)
			chain := strings.Join(result.RedirectChain, " --> ")
			color.Green("[VULNERABLE] %s redirects to %s", result.FuzzedURL, chain)
		} else if verbose {
			color.Yellow("[INFO] %s (Status: %d)", result.FuzzedURL, result.StatusCode)
		}
	}

	color.Cyan("Scan completed. Found %d vulnerable URLs.", len(vulnerableURLs))

	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			color.Red("Error creating output file: %v", err)
		} else {
			defer f.Close()
			for _, vuln := range vulnerableURLs {
				fmt.Fprintf(f, "Original: %s\nFuzzed: %s\nChain: %s\n\n", 
					vuln.OriginalURL, vuln.FuzzedURL, strings.Join(vuln.RedirectChain, " --> "))
			}
			color.Green("Results written to %s", outputFile)
		}
	}
}
