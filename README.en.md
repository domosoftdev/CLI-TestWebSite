[Lire en français](README.md)

# Web Security Checker

A simple command-line tool to perform basic security checks on a website.

## Description

This Python script analyzes a given URL to assess certain aspects of its security configuration. It is a basic tool intended to provide a quick overview of a web server's security posture.

## Features

The tool performs the following checks:

1.  **SSL/TLS Certificate**: Verifies the chain of trust and expiration date.
2.  **HTTP Security Headers**: Analyzes the presence and configuration of headers like `Strict-Transport-Security`, `X-Frame-Options`, etc.
3.  **HTTPS Redirections**: Ensures that unsecured traffic is redirected to HTTPS.
4.  **Supported SSL/TLS Protocols**: Detects obsolete and vulnerable protocol versions.
5.  **Security DNS Records**: Checks for the presence of records like `DMARC` and `SPF`.
6.  **Cookie Attributes**: Analyzes `HttpOnly`, `Secure`, and `SameSite` attributes.
7.  **WHOIS Information**: Retrieves public domain data.
8.  **Parking Score**: Assesses the probability that a domain is "parked".

## Installation

1.  Make sure you have Python 3 installed on your system.
2.  Clone this repository.
3.  Install the necessary dependencies using pip:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

The application is now centralized in `main.py` and is operated via command-line arguments.

### Running a New Scan

To analyze a website, use the `--domain` argument.

```bash
python3 main.py --domain google.com
```

#### Specifying the Output Directory

By default, reports are saved in a `scans/` directory. You can specify a different directory using the `--scans-dir` argument. This directory will be used for both reading existing scans and saving new reports.

```bash
python3 main.py --domain google.com --formats json --scans-dir /path/to/my/reports
```

#### Generating Reports

You can generate reports in JSON, CSV, or HTML format using the `--formats` argument.

```bash
python3 main.py --domain google.com --formats json,csv,html
```

### Analyzing Existing Scans

The tool provides several commands to analyze the history of scans you have generated.

#### List Scans for a Domain

Use `--list-scans` to see all saved reports for a domain.

```bash
python3 main.py --list-scans google.com
```

#### Compare Two Scans

Use `--compare` to see the changes (regressions or improvements) between two dates.

```bash
python3 main.py --compare google.com 2025-08-17 2025-08-18
```

#### Generate an Evolution Graph

Use `--graph` to generate an image (`<domain>_evolution.png`) showing the evolution of the security score over time.

**Important Note:** This feature generates a static image file. There is **no** interactive web application.

```bash
python3 main.py --graph google.com
```

The graph will be saved in the directory specified by `--scans-dir` (or `scans/` by default).

#### Other Reporting Commands

Other commands like `--status`, `--oldest`, `--quick-wins`, etc., are also available. Use `python3 main.py --help` to see the full list of options.
