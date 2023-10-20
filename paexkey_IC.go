package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

type Result struct {
	Source string
	URL    string
	Where  string
}

var dnsServers = []string{
	"8.8.8.8",   // Google Public DNS (IPv4)
	"1.1.1.1",   // Cloudflare DNS (IPv4)
	"208.67.222.222", // OpenDNS (IPv4)
	"9.9.9.9",   // Quad9 DNS (IPv4)
	"75.75.75.75", // Comcast DNS (IPv4)
	"2001:4860:4860::8888", // Google Public DNS (IPv6)
	"2606:4700:4700::1111", // Cloudflare DNS (IPv6)
	"2620:0:ccc::2", // OpenDNS (IPv6)
	"2620:fe::9",    // Quad9 DNS (IPv6)
	"2001:558:feed::1", // Comcast DNS (IPv6)
	"209.244.0.3",
	"209.244.0.4",
	"8.8.4.4",
	"8.26.56.26",
	"8.20.247.20",
	"208.67.222.222",
	"208.67.220.220",
	"156.154.70.1",
	"156.154.71.1",
	"199.85.126.10",
	"199.85.127.10",
	"81.218.119.11",
	"209.88.198.133",
	"195.46.39.39",
	"195.46.39.40",
	"216.87.84.211",
	"23.90.4.6",
	"199.5.157.131",
	"208.71.35.137",
	"208.76.50.50",
	"208.76.51.51",
	"216.146.35.35",
	"216.146.36.36",
	"89.233.43.71",
	"89.104.194.142",
	"74.82.42.42",
	"109.69.8.51",
}

var headers map[string]string
var keywords []string
var keywordMatchedURLs []string
var mutex = &sync.Mutex{}

// Thread safe map
var sm sync.Map

func main() {
	inside := flag.Bool("i", false, "Only crawl inside path")
	threads := flag.Int("t", 8, "Number of threads to utilize.")
	depth := flag.Int("d", 2, "Depth to crawl.")
	maxSize := flag.Int("size", -1, "Page size limit, in KB.")
	insecure := flag.Bool("insecure", false, "Disable TLS verification.")
	subsInScope := flag.Bool("subs", false, "Include subdomains for crawling.")
	showJson := flag.Bool("json", false, "Output as JSON.")
	showSource := flag.Bool("s", false, "Show the source of URL based on where it was found. E.g. href, form, script, etc.")
	showWhere := flag.Bool("w", false, "Show at which link the URL is found.")
	unique := flag.Bool("u", false, "Show only unique URLs.")
	proxy := flag.String("proxy", "", "Proxy URL. E.g. -proxy http://127.0.0.1:8080")
	timeout := flag.Int("timeout", -1, "Maximum time to crawl each URL from stdin, in seconds.")
	disableRedirects := flag.Bool("dr", false, "Disable following HTTP redirects.")
	keywordFile := flag.String("k", "", "Path to a wordlist file containing keywords.")

	flag.Parse()

	// Create a wait group to wait for the goroutine to finish
	var wg sync.WaitGroup

	// Open the file for writing or append if it exists
	outputFile, err := os.OpenFile("matched_urls.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	// Create a writer for the output file
	const bufferSize = 10 * 1024 * 1024 // 20MB
	outputWriter := bufio.NewWriterSize(outputFile, bufferSize)
	defer outputWriter.Flush()

	if *keywordFile != "" {
		keywords, err = loadKeywordsFromFile(*keywordFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error loading keywords from file:", err)
			os.Exit(1)
		}
	}

	if *proxy != "" {
		os.Setenv("PROXY", *proxy)
	}
	proxyURL, _ := url.Parse(os.Getenv("PROXY"))

	// Check for stdin input
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "No urls detected. Hint: cat urls.txt | hakrawler")
		os.Exit(1)
	}

	results := make(chan string, *threads)
	// Increment the wait group counter
	wg.Add(1)
	go func() {
		defer wg.Done() // Decrement the wait group counter when done
		// get each line of stdin, push it to the work channel
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			url := s.Text()
			hostname, err := extractHostname(url)
			if err != nil {
				log.Println("Error parsing URL:", err)
				continue
			}

			allowed_domains := []string{hostname}
			// if "Host" header is set, append it to allowed domains
			if headers != nil {
				if val, ok := headers["Host"]; ok {
					allowed_domains = append(allowed_domains, val)
				}
			}

			// Instantiate default collector
			c := colly.NewCollector(
				// default user agent header
				colly.UserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"),
				// limit crawling to the domain of the specified URL
				colly.AllowedDomains(allowed_domains...),
				// set MaxDepth to the specified depth
				colly.MaxDepth(*depth),
				// specify Async for threading
				colly.Async(true),
			)

			// set a page size limit
			if *maxSize != -1 {
				c.MaxBodySize = *maxSize * 1024
			}

			// if -subs is present, use regex to filter out subdomains in scope.
			if *subsInScope {
				c.AllowedDomains = nil
				c.URLFilters = []*regexp.Regexp{regexp.MustCompile(".*(\\.|\\/\\/)" + strings.ReplaceAll(hostname, ".", "\\.") + "((#|\\/|\\?).*)?")}
			}

			// If `-dr` flag provided, do not follow HTTP redirects.
			if *disableRedirects {
				c.SetRedirectHandler(func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				})
			}
			// Set parallelism
			c.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: *threads})

			// Print every href found, and visit it
			c.OnHTML("a[href]", func(e *colly.HTMLElement) {
				link := e.Attr("href")
				abs_link := e.Request.AbsoluteURL(link)
				if strings.Contains(abs_link, url) || !*inside {
					printResult(link, "href", *showSource, *showWhere, *showJson, results, e, outputWriter)
					e.Request.Visit(link)
				}
			})

			// find and print all the JavaScript files
			c.OnHTML("script[src]", func(e *colly.HTMLElement) {
				printResult(e.Attr("src"), "script", *showSource, *showWhere, *showJson, results, e, outputWriter)
			})

			// find and print all the form action URLs
			c.OnHTML("form[action]", func(e *colly.HTMLElement) {
				printResult(e.Attr("action"), "form", *showSource, *showWhere, *showJson, results, e, outputWriter)
			})

			// Extract URLs from JavaScript code
			c.OnHTML("script", func(e *colly.HTMLElement) {
				jsCode := e.Text
				urls := extractURLsFromJS(jsCode)
				for _, url := range urls {
					printResult(url, "jscode", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from CSS files
			c.OnHTML("link[rel=stylesheet]", func(e *colly.HTMLElement) {
				cssURL := e.Attr("href")
				printResult(cssURL, "css", *showSource, *showWhere, *showJson, results, e, outputWriter)
			})

			// Extract URLs from embedded resources, iframes, img tags, data attributes, and HTTP redirects
			c.OnHTML("[src], iframe, img, [data-*]", func(e *colly.HTMLElement) {
				srcURL := e.Attr("src")
				if srcURL != "" {
					printResult(srcURL, "embedded", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract interactive element URLs if they have absolute URLs
			c.OnHTML("button[href], a[href], form[action], select", func(e *colly.HTMLElement) {
				link := e.Attr("href")
				if link != "" && (strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://")) {
					printResult(link, "interactive", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs using the custom regular expression pattern
			c.OnHTML("*", func(e *colly.HTMLElement) {
				body := e.Text
				urls := extractURLsWithCustomPattern(body)
				for _, url := range urls {
					printResult(url, "custom_REGEX", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from all HTML elements and attributes
			c.OnHTML("*", func(e *colly.HTMLElement) {
				// Check for href attribute
				href := e.Attr("href")
				if href != "" {
					printResult(href, "href", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}

				// Check for src attribute
				src := e.Attr("src")
				if src != "" {
					printResult(src, "src", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}

				//Check for data attributes that may contain URLs
				e.ForEach("[data-*]", func(_ int, el *colly.HTMLElement) {
					dataAttr := el.Text
					if dataAttr != "" {
						printResult(dataAttr, "data", *showSource, *showWhere, *showJson, results, e, outputWriter)
					}
				})

				// Check for content attribute in meta tags
				if e.Name == "meta" {
					content := e.Attr("content")
					if content != "" {
						printResult(content, "meta", *showSource, *showWhere, *showJson, results, e, outputWriter)
					}
				}

				// Check for URLs in inline JavaScript code
				if e.Name == "script" {
					jsCode := e.Text
					urls := extractURLsFromJS(jsCode)
					for _, url := range urls {
						printResult(url, "jscode", *showSource, *showWhere, *showJson, results, e, outputWriter)
					}
				}

				// Check for URLs in CSS files
				if e.Name == "link" && e.Attr("rel") == "stylesheet" {
					cssURL := e.Attr("href")
					printResult(cssURL, "css", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}

				//Check for custom data attributes that may contain URLs
				e.ForEach("[data-custom-*]", func(_ int, el *colly.HTMLElement) {
					customDataAttr := el.Text
					if customDataAttr != "" {
						printResult(customDataAttr, "custom-data", *showSource, *showWhere, *showJson, results, e, outputWriter)
					}
				})

				//Add more checks for specific elements and attributes here
			})

			// Extract URLs from <video> tags
			c.OnHTML("video[src]", func(e *colly.HTMLElement) {
				src := e.Attr("src")
				if src != "" {
					printResult(src, "video", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from <audio> tags
			c.OnHTML("audio[src]", func(e *colly.HTMLElement) {
				src := e.Attr("src")
				if src != "" {
					printResult(src, "audio", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from <embed> tags
			c.OnHTML("embed[src]", func(e *colly.HTMLElement) {
				src := e.Attr("src")
				if src != "" {
					printResult(src, "embed", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from <track> tags
			c.OnHTML("track[src]", func(e *colly.HTMLElement) {
				src := e.Attr("src")
				if src != "" {
					printResult(src, "track", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from <area> tags
			c.OnHTML("area[href]", func(e *colly.HTMLElement) {
				href := e.Attr("href")
				if href != "" {
					printResult(href, "area", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from <applet> tags
			c.OnHTML("applet[archive]", func(e *colly.HTMLElement) {
				archive := e.Attr("archive")
				if archive != "" {
					printResult(archive, "applet", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from <base> tags
			c.OnHTML("base[href]", func(e *colly.HTMLElement) {
				href := e.Attr("href")
				if href != "" {
					printResult(href, "base", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from <bgsound> tags
			c.OnHTML("bgsound[src]", func(e *colly.HTMLElement) {
				src := e.Attr("src")
				if src != "" {
					printResult(src, "bgsound", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from <body> background attribute
			c.OnHTML("body[background]", func(e *colly.HTMLElement) {
				background := e.Attr("background")
				if background != "" {
					printResult(background, "body-background", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from XML and RSS feeds
			c.OnHTML("link[type='application/rss+xml'], link[type='application/atom+xml'], link[type='application/xml']", func(e *colly.HTMLElement) {
				feedURL := e.Attr("href")
				if feedURL != "" {
					printResult(feedURL, "feed", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from WebP images
			c.OnHTML("img[src*='.webp']", func(e *colly.HTMLElement) {
				webpURL := e.Attr("src")
				if webpURL != "" {
					printResult(webpURL, "webp-image", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from web manifest files
			c.OnHTML("link[rel='manifest']", func(e *colly.HTMLElement) {
				manifestURL := e.Attr("href")
				if manifestURL != "" {
					printResult(manifestURL, "manifest", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from social media meta tags (Open Graph and Twitter)
			c.OnHTML("meta[property^='og:'], meta[name^='twitter:']", func(e *colly.HTMLElement) {
				property := e.Attr("property")
				name := e.Attr("name")
				content := e.Attr("content")

				if property != "" && content != "" {
					printResult(content, "social-media-"+property, *showSource, *showWhere, *showJson, results, e, outputWriter)
				} else if name != "" && content != "" {
					printResult(content, "social-media-"+name, *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from XML sitemaps
			c.OnHTML("a[href$='.xml']", func(e *colly.HTMLElement) {
				sitemapURL := e.Attr("href")
				if sitemapURL != "" {
					printResult(sitemapURL, "sitemap", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from data URIs
			c.OnHTML("*[src^='data:']", func(e *colly.HTMLElement) {
				dataURI := e.Attr("src")
				if dataURI != "" {
					printResult(dataURI, "data-uri", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract WebSocket URLs
			c.OnHTML("script[src^='ws://'], script[src^='wss://']", func(e *colly.HTMLElement) {
				websocketURL := e.Attr("src")
				if websocketURL != "" {
					printResult(websocketURL, "websocket", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// Extract URLs from frame sources
			c.OnHTML("frame[src], frameset[frameborder='1']", func(e *colly.HTMLElement) {
				frameURL := e.Attr("src")
				if frameURL != "" {
					printResult(frameURL, "frame", *showSource, *showWhere, *showJson, results, e, outputWriter)
				}
			})

			// add the custom headers
			if headers != nil {
				c.OnRequest(func(r *colly.Request) {
					for header, value := range headers {
						r.Headers.Set(header, value)
					}
				})
			}

			if *proxy != "" {
				// Skip TLS verification for proxy, if -insecure specified
				c.WithTransport(&http.Transport{
					Proxy:           http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
				})
			} else {
				// Skip TLS verification if -insecure flag is present
				c.WithTransport(&http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
				})
			}

			if *timeout == -1 || isURLAlive(url, *timeout) {
				// Check if URL is truly alive
				if isURLAlive(url, *timeout) {
					// Start scraping
					c.Visit(url)
					// Wait until threads are finished
					c.Wait()
					runtime.GC()
					log.Println("[CRAWLED]: " + url)
				} else {
					log.Println("[URL UNREACHABLE]: " + url)
					runtime.GC()
				}
			} else {
				log.Println("[URL UNREACHABLE]: " + url)
				runtime.GC()
			}

		}
		if err := s.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "reading standard input:", err)
		}
	}()

	// Wait for the goroutine to complete with a timeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Wait for a reasonable amount of time (adjust as needed)
		timeoutDuration := time.Duration(*timeout) * time.Second
		select {
		case <-time.After(timeoutDuration):
			log.Println("[DONE]: Closing goroutine as it complete")
		case <-done:
			// The goroutine completed successfully
		}
	}()

	// Wait for the goroutine to complete
	wg.Wait()

	// Close the results channel
	close(results)

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	if *unique {
		for res := range results {
			if isUnique(res) {
				// Print the unique URL
				fmt.Fprintln(w, res)
			}
		}
	}
	for res := range results {
		// Print the unique URL
		fmt.Fprintln(w, res)
	}
}

// parseHeaders does validation of headers input and saves it to a formatted map.
func parseHeaders(rawHeaders string) error {
	if rawHeaders != "" {
		if !strings.Contains(rawHeaders, ":") {
			return errors.New("headers flag not formatted properly (no colon to separate header and value)")
		}

		headers = make(map[string]string)
		rawHeaders := strings.Split(rawHeaders, ";;")
		for _, header := range rawHeaders {
			var parts []string
			if strings.Contains(header, ": ") {
				parts = strings.SplitN(header, ": ", 2)
			} else if strings.Contains(header, ":") {
				parts = strings.SplitN(header, ":", 2)
			} else {
				continue
			}
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return nil
}

// extractHostname() extracts the hostname from a URL and returns it
func extractHostname(urlString string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil || !u.IsAbs() {
		return "", errors.New("Input must be a valid absolute URL")
	}

	return u.Hostname(), nil
}

func printResult(link string, sourceName string, showSource bool, showWhere bool, showJson bool, results chan string, e *colly.HTMLElement, outputWriter *bufio.Writer) {
	// Check if keywords are provided and if any of them are present in the URL
	if len(keywords) == 0 || containsKeyword(link, keywords) {
		result := e.Request.AbsoluteURL(link)
		whereURL := e.Request.URL.String()
		if result != "" {
			if showJson {
				where := ""
				if showWhere {
					where = whereURL
				}
				bytes, _ := json.Marshal(Result{
					Source: sourceName,
					URL:    result,
					Where:  where,
				})
				result = string(bytes)
			} else if showSource {
				result = "[" + sourceName + "] " + result
			}

			if showWhere && !showJson {
				result = "[" + whereURL + "] " + result
			}

			// Lock the mutex before writing to the file
			mutex.Lock()

			// If timeout occurs before goroutines are finished, recover from panic that may occur when attempting writing to results to closed results channel
			defer func() {
				if err := recover(); err != nil {
					return
				}
			}()
			results <- result

			// Save URLs containing keywords to the file
			if len(keywords) == 0 || containsKeyword(result, keywords) {
				_, err := outputWriter.WriteString(result + "\n")
				if err != nil {
					log.Println("Error writing URL to file:", err)
				}
			}
			defer mutex.Unlock()
		}
	}
}

// Function to check if any keyword is present in the URL
func containsKeyword(url string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(url, keyword) {
			return true
		}
	}
	return false
}

// returns whether the supplied url is unique or not
func isUnique(url string) bool {
	_, present := sm.Load(url)
	if present {
		return false
	}
	sm.Store(url, true)
	return true
}

func extractURLsFromJS(jsCode string) []string {
	// Regular expression pattern to match URLs in JavaScript code
	regex := regexp.MustCompile(`(?i)(?:(?:https?|ftp|smtp|unknown|sftp|file|data|telnet|ssh|ws|wss|git|svn|gopher):\/\/)(?:(?:[^\s:@'"]+(?::[^\s:@'"]*)?@)?(?:[_A-Z0-9.-]+|\[[_A-F0-9]*:[_A-F0-9:]+\])(?::\d{1,5})?)(?:\/[^\s'"]*)?(?:\?[^\s'"]*)?(?:#[^\s'"]*)?`)
	matches := regex.FindAllString(jsCode, -1)

	// Deduplicate the matches (if needed)
	uniqueURLs := make(map[string]bool)
	for _, match := range matches {
		uniqueURLs[match] = true
	}

	// Convert unique URLs to a slice
	var urls []string
	for url := range uniqueURLs {
		urls = append(urls, url)
	}

	return urls
}

func extractURLsWithCustomPattern(body string) []string {
	// Define your custom regular expression pattern here
	customRegexPattern := `(?i)(?:(?:https?|ftp|smtp|unknown|sftp|file|data|telnet|ssh|ws|wss|git|svn|gopher):\/\/)(?:(?:[^\s:@'"]+(?::[^\s:@'"]*)?@)?(?:[_A-Z0-9.-]+|\[[_A-F0-9]*:[_A-F0-9:]+\])(?::\d{1,5})?)(?:\/[^\s'"]*)?(?:\?[^\s'"]*)?(?:#[^\s'"]*)?`

	// Regular expression pattern to match URLs based on the custom pattern
	regex := regexp.MustCompile(customRegexPattern)
	matches := regex.FindAllString(body, -1)

	// Deduplicate the matches (if needed)
	uniqueURLs := make(map[string]bool)
	for _, match := range matches {
		uniqueURLs[match] = true
	}

	// Convert unique URLs to a slice
	var urls []string
	for url := range uniqueURLs {
		urls = append(urls, url)
	}

	return urls
}

func loadKeywordsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var keywords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		keyword := scanner.Text()
		keywords = append(keywords, keyword)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return keywords, nil
}

func isURLAlive(url string, timeout int) bool {
	// Check for network connectivity
	for {
		if isInternetConnected() {
			break
		}
		log.Println("Waiting for internet connection...")
		time.Sleep(1 * time.Second) // Wait for 30 seconds before rechecking
	}

	// Attempt to resolve the hostname from the URL
	host, err := extractHostname(url)
	if err != nil {
		log.Printf("[INVALID URL]: %s\n", url)
		return false
	}

	// Check DNS resolution
	ips, err := net.LookupIP(host)
	if err != nil {
		// log.Printf("[DNS ERROR]: Unable to resolve host %s: %v\n", host, err)
		return false
	}

	if len(ips) == 0 {
		// log.Printf("[NO IP ADDRESSES]: No IP addresses found for host %s\n", host)
		return false
	}

	// Define the maximum number of retries
	maxRetries := 4
	for i := 0; i < maxRetries; i++ {
		client := http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}
		resp, err := client.Head(url)
		if err != nil {
			// Handle network errors
			// log.Printf("[NETWORK ERROR]: %s, Retry #%d\n", url, i+1)
			time.Sleep(15 * time.Second) // Wait before retry
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			// URL is alive and within expected range (200-399)
			return true
		} else if resp.StatusCode == http.StatusTooManyRequests {
			// Handle rate limiting or temporary unavailability
			// log.Printf("[RATE LIMITING]: %s, Status Code: %d, Retry #%d\n", url, resp.StatusCode, i+1)
			time.Sleep(20 * time.Second) // Wait before retry
		} else if resp.StatusCode >= 500 {
			// Retry if it's a server error (500+)
			// log.Printf("[RETRYING]: %s - Status: %d\n", url, resp.StatusCode)
			time.Sleep(10 * time.Second)
		} else if resp.StatusCode == 404 || resp.StatusCode == 403 || resp.StatusCode == 401 || resp.StatusCode == 400 {
			// Skip the URL for specific status codes (400, 401, 403, 404)
			// log.Printf("[SKIPPING]: %s - Status: %d\n", url, resp.StatusCode)
			return false
		} else {
			// Handle other non-OK status codes
			log.Printf("[HTTP STATUS]: %s, Status Code: %d, Retry #%d\n", url, resp.StatusCode, i+1)
			time.Sleep(5 * time.Second) // Wait before retry
		}
	}
	return fmt.Errorf("[MAX RETRIES EXCEEDED]: %s", url)
}


func isInternetConnected() bool {
	for {
		for _, dnsServer := range dnsServers {
			_, err := net.LookupHost(dnsServer)
			if err == nil {
				return true
			} else {
				log.Println("Waiting for internet connection...")
			}
		}
		time.Sleep(5 * time.Second) // Wait for 5 seconds before rechecking
	}
}
