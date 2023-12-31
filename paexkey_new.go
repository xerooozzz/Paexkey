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

	// Check for network connectivity
	for {
		if isInternetConnected() {
			break
		}
		log.Println("Waiting for internet connection...")
		time.Sleep(30 * time.Second) // Wait for 30 seconds before rechecking
	}

    // Initialize the wait group outside of the loop
    var wg sync.WaitGroup

    // Open the output file
    outputFile, err := os.OpenFile("matched_urls.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
    if err != nil {
        log.Fatal(err)
    }
    defer outputFile.Close()

    // Create a buffered writer for the output file
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

    // Check for stdin input
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "No urls detected. Hint: cat urls.txt | paexkey")
		os.Exit(1)
	}

    // Set up proxy if provided
    var proxyURL *url.URL
    if *proxy != "" {
        var err error
        proxyURL, err = url.Parse(*proxy)
        if err != nil {
            log.Fatalf("Error parsing proxy URL: %v", err)
        }
    }

    // Use a single transport instance to benefit from connection reuse
    transport := &http.Transport{
        Proxy:           http.ProxyURL(proxyURL),
        TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
    }

    // Set up channels for results and for indicating when processing is done
    results := make(chan string, 100)
    done := make(chan bool)

    // Launch a single goroutine for processing results
    wg.Add(1)
    go func() {
        defer wg.Done()
        w := bufio.NewWriter(os.Stdout)
        defer w.Flush()
        if *unique {
            for res := range results {
                if isUnique(res) {
                    // Print the unique URL
                    fmt.Fprintln(w, res)
                }
            }
        }else {
		for res := range results {
			// Print the unique URL
			fmt.Fprintln(w, res)
		}
	}
    }()

    // Read from stdin
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

		c.WithTransport(transport)

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

	// Extract URLs from all HTML elements and attributes
	c.OnHTML("*", func(e *colly.HTMLElement) {
	    e.ForEach("a[href], script[src]:not([src^='ws://']):not([src^='wss://']), form[action], link[rel=stylesheet], [src], iframe, img, [data-*], button[href], area[href], applet[archive], base[href], bgsound[src], body[background], video[src], audio[src], embed[src], track[src], link[type='application/rss+xml'], link[type='application/atom+xml'], link[type='application/xml'], img[src*='.webp'], link[rel='manifest'], meta[property^='og:'], meta[name^='twitter:'], a[href$='.xml'], *[src^='data:'], script[src^='ws://'], script[src^='wss://'], frame[src], frameset[frameborder='1']", func(_ int, el *colly.HTMLElement) {
	        resourceType := ""
	        attr := ""
	        switch true {
	        case el.Name == "a" && el.Attr("href") != "":
	            resourceType = "href"
	            attr = el.Attr("href")
	        case el.Name == "script" && el.Attr("src") != "":
	            resourceType = "script"
	            attr = el.Attr("src")
	        case el.Name == "form" && el.Attr("action") != "":
	            resourceType = "form"
	            attr = el.Attr("action")
	        case el.Name == "link" && el.Attr("rel") == "stylesheet":
	            resourceType = "css"
	            attr = el.Attr("href")
	        case el.Name == "img" && strings.Contains(el.Attr("src"), ".webp"):
	            resourceType = "webp-image"
	            attr = el.Attr("src")
	        case el.Name == "link" && el.Attr("rel") == "manifest":
	            resourceType = "manifest"
	            attr = el.Attr("href")
	        case el.Name == "meta" && (strings.HasPrefix(el.Attr("property"), "og:") || strings.HasPrefix(el.Attr("name"), "twitter:")):
	            if el.Attr("property") != "" {
	                resourceType = "social-media-" + el.Attr("property")
	            } else {
	                resourceType = "social-media-" + el.Attr("name")
	            }
	            attr = el.Attr("content")
	        case el.Name == "a" && strings.HasSuffix(el.Attr("href"), ".xml"):
	            resourceType = "sitemap"
	            attr = el.Attr("href")
	        case el.Attr("src") != "" && (strings.HasPrefix(el.Attr("src"), "ws://") || strings.HasPrefix(el.Attr("src"), "wss://")):
	            resourceType = "websocket"
	            attr = el.Attr("src")
	        case el.Name == "frame" && el.Attr("src") != "":
	            resourceType = "frame"
	            attr = el.Attr("src")
	        case el.Attr("src") != "":
	            resourceType = "embedded"
	            attr = el.Attr("src")
	        }
	
	        if attr != "" {
	            abs_attr := e.Request.AbsoluteURL(attr)
	            if strings.Contains(abs_attr, url) || !*inside {
	                printResult(attr, resourceType, *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
	                if resourceType == "href" {
	                    e.Request.Visit(attr)
	                }
	            }
	        } else if el.Name == "script" && el.Attr("src") == "" {
	            jsCode := el.Text
	            urls := extractURLsFromJS(jsCode)
	            for _, url := range urls {
	                printResult(url, "jscode", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
	            }
	        }
	    })
	
	    // Check for URLs in inline JavaScript code
	    if e.Name == "script" && e.Attr("src") == "" {
	        jsCode := e.Text
	        urls := extractURLsFromJS(jsCode)
	        for _, url := range urls {
	            printResult(url, "jscode", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
	        }
	    }
	
	    // Check for URLs using the custom regular expression pattern
	    body := e.Text
	    urls := extractURLsWithCustomPattern(body)
	    for _, url := range urls {
	        printResult(url, "custom_REGEX", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
	    }
	
	    // Check for data attributes that may contain URLs
	    e.ForEach("[data-*]", func(_ int, el *colly.HTMLElement) {
	        dataAttr := el.Text
	        if dataAttr != "" {
	            printResult(dataAttr, "data", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
	        }
	    })
	
	    // Check for custom data attributes that may contain URLs
	    e.ForEach("[data-custom-*]", func(_ int, el *colly.HTMLElement) {
	        customDataAttr := el.Text
	        if customDataAttr != "" {
	            printResult(customDataAttr, "custom-data", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
	        }
	    })
	})

        c.Wait()

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

        // Start scraping in a goroutine
        wg.Add(1)
        go func(url string) {
            defer wg.Done()
            if isURLAlive(url, *timeout) {
                // Start scraping
                c.Visit(url)
                // Wait until threads are finished
                c.Wait()
                log.Println("[CRAWLED]: " + url)
            } else {
                log.Printf("[URL UNREACHABLE]: %s\n", url)
            }
            done <- true
        }(url)
    }

    // Close the results channel when all goroutines are done
    go func() {
        wg.Wait()
        close(results)
        close(done)
    }()

    // Block until the processing is done
    <-done

    if err := s.Err(); err != nil {
        log.Fatalf("reading standard input: %v", err)
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

func printResult(link string, sourceName string, showSource bool, showWhere bool, showJson bool, results chan string, e *colly.HTMLElement, outputWriter *bufio.Writer, outputFile *os.File) {
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

			// Save URLs containing keywords to the file
			if len(keywords) == 0 || containsKeyword(result, keywords) {
				_, err := outputWriter.WriteString(result + "\n")
				if err != nil {
					log.Println("Error writing URL to file:", err)
				}
				outputWriter.Flush() // Flush immediately to save to the file
				outputFile.Close()   // Close the file after flushing
			}

			// Unlock the mutex
			defer mutex.Unlock()

			// If timeout occurs before goroutines are finished, recover from panic that may occur when attempting writing to results to the closed results channel
			defer func() {
				if err := recover(); err != nil {
					return
				}
			}()

			// Send the result to the channel
			results <- result
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
		time.Sleep(30 * time.Second) // Wait for 30 seconds before rechecking
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
	maxRetries := 2
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

	// All retries failed, URL is not reachable
	// log.Printf("[URL UNREACHABLE]: %s\n", url)
	return false
}

func isInternetConnected() bool {
	// Check if there's an active network connection
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Println("[INTERNET CHECK ERROR]:", err)
		return false
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return true
			}
		}
	}
	return false
}
