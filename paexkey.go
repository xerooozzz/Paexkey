package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
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


// Thread safe map
var sm sync.Map

func main() {
	inside := flag.Bool("i", false, "Only crawl inside path")
	threads := flag.Int("t", 8, "Number of threads to utilise.")
	depth := flag.Int("d", 2, "Depth to crawl.")
	maxSize := flag.Int("size", -1, "Page size limit, in KB.")
	insecure := flag.Bool("insecure", false, "Disable TLS verification.")
	subsInScope := flag.Bool("subs", false, "Include subdomains for crawling.")
	showJson := flag.Bool("json", false, "Output as JSON.")
	showSource := flag.Bool("s", false, "Show the source of URL based on where it was found. E.g. href, form, script, etc.")
	showWhere := flag.Bool("w", false, "Show at which link the URL is found.")
	unique := flag.Bool(("u"), false, "Show only unique urls.")
	proxy := flag.String(("proxy"), "", "Proxy URL. E.g. -proxy http://127.0.0.1:8080")
	timeout := flag.Int("timeout", -1, "Maximum time to crawl each URL from stdin, in seconds.")
	disableRedirects := flag.Bool("dr", false, "Disable following HTTP redirects.")
	keywordFile := flag.String("k", "", "Path to a wordlist file containing keywords.")

	flag.Parse()

    var err error // Add this line
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
	go func() {
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
				// set custom headers
				// colly.Headers(headers),
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

					printResult(link, "href", *showSource, *showWhere, *showJson, results, e)
					e.Request.Visit(link)
				}
			})

			// find and print all the JavaScript files
			c.OnHTML("script[src]", func(e *colly.HTMLElement) {
				printResult(e.Attr("src"), "script", *showSource, *showWhere, *showJson, results, e)
			})

			// find and print all the form action URLs
			c.OnHTML("form[action]", func(e *colly.HTMLElement) {
				printResult(e.Attr("action"), "form", *showSource, *showWhere, *showJson, results, e)
			})

			// Extract URLs from JavaScript code
			c.OnHTML("script", func(e *colly.HTMLElement) {
				jsCode := e.Text
				urls := extractURLsFromJS(jsCode)
				for _, url := range urls {
					printResult(url, "jscode", *showSource, *showWhere, *showJson, results, e)
				}
			})
		
			// Extract URLs from CSS files
			c.OnHTML("link[rel=stylesheet]", func(e *colly.HTMLElement) {
				cssURL := e.Attr("href")
				printResult(cssURL, "css", *showSource, *showWhere, *showJson, results, e)
			})
		
			// Extract URLs from embedded resources, iframes, img tags, data attributes, and HTTP redirects
			c.OnHTML("[src], iframe, img, [data-*]", func(e *colly.HTMLElement) {
				srcURL := e.Attr("src")
				if srcURL != "" {
					printResult(srcURL, "embedded", *showSource, *showWhere, *showJson, results, e)
				}
			})
		
			// Extract interactive element URLs if they have absolute URLs
			c.OnHTML("button[href], a[href], form[action], select", func(e *colly.HTMLElement) {
				link := e.Attr("href")
				if link != "" && strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
					printResult(link, "interactive", *showSource, *showWhere, *showJson, results, e)
				}
			})
		
			// Extract URLs using the custom regular expression pattern
			c.OnHTML("*", func(e *colly.HTMLElement) {
				body := e.Text
				urls := extractURLsWithCustomPattern(body)
				for _, url := range urls {
					printResult(url, "custom_REGEX", *showSource, *showWhere, *showJson, results, e)
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

			if *timeout == -1 {
				// Start scraping
				c.Visit(url)
				// Wait until threads are finished
				c.Wait()
			} else {
				finished := make(chan int, 1)

				go func() {
					// Start scraping
					c.Visit(url)
					// Wait until threads are finished
					c.Wait()
					finished <- 0
				}()

				select {
				case _ = <-finished: // the crawling finished before the timeout
					close(finished)
					continue
				case <-time.After(time.Duration(*timeout) * time.Second): // timeout reached
					log.Println("[timeout] " + url)
					continue

				}
			}

		}
		if err := s.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "reading standard input:", err)
		}
		close(results)
	}()

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	if *unique {
		for res := range results {
			if isUnique(res) {
				fmt.Fprintln(w, res)
			}
		}
	}
	for res := range results {
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

func printResult(link string, sourceName string, showSource bool, showWhere bool, showJson bool, results chan string, e *colly.HTMLElement) {
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

            // If timeout occurs before goroutines are finished, recover from panic that may occur when attempting writing to results to closed results channel
            defer func() {
                if err := recover(); err != nil {
                    return
                }
            }()
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

