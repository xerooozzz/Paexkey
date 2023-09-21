# Paexkey

![GitHub](https://img.shields.io/github/license/xerooozzz/Paexkey)
![GitHub last commit](https://img.shields.io/github/last-commit/xerooozzz/Paexkey)
![GitHub issues](https://img.shields.io/github/issues/xerooozzz/Paexkey)
![GitHub stars](https://img.shields.io/github/stars/xerooozzz/Paexkey)

## Overview

Welcome to the Web Crawler and URL Extractor! This Python script is designed for cybersecurity analysts, bug hunters, and web security enthusiasts. It empowers you to efficiently extract URLs from web pages, supporting both WEB2 and WEB3 technologies. You can even perform keyword-based URL filtering to enhance your web security analysis.

## Features

- **URL Extraction**: Extract URLs from web pages effortlessly.
- **WEB2 and WEB3 Support**: Navigate the evolving web landscape with ease.
- **Keyword Filtering**: Filter URLs based on keywords for targeted analysis.
- **Customizable Depth**: Adjust the depth of URL extraction to your needs.
- **Multi-threaded Processing**: Enhance efficiency with multi-threading.
- **Verbose Mode**: Enable detailed logging for insights.
- **Easy Setup**: Get started quickly with straightforward configuration.

## Usage

1. **Clone the Repository**:
   
   ```shell
   git clone https://github.com/Paexkey/Web-Crawler-URL-Extractor.git
   ```
3. **Install Requirements**:
   
   ```shell
   cd Paexkey
   ```
   
   ```shell
   pip3 install -r requirements.txt
   ```

5. **Run script**:

   ```shell
   python3 paexkey.py <url> -o <output_directory> -d <depth> -t <threads> -v -k <keywords_list>
   ```

   For long List of urls:

   ```shell
   cat <url_list> | xargs -n 10 -P 10 -I {} python3 paexkey.py {} -o <output_directory> -d <depth> -t <threads> -v  k <keywords_list>
   ```


- `<url_file>`: File containing starting URLs.
- `<output_directory>`: Output directory for extracted URLs.
- `<depth>`: Depth of URL extraction.
- `<threads>`: Number of threads to use.
- `-v`: Enable verbose mode.
- `<keywords_list>`: Path of Keywords lists line delimited file path.
- `-i`: Delete Output file only keep Filtered Keywords URL list. Suggested for very long URL list.

## Tags

#WebCrawler #URLExtractor #Cybersecurity #BugHunting #WebSecurity #PythonScript

Explore this powerful tool for web security professionals and bug hunters.

