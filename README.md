# ETW Go

ETW Go is a comprehensive tool for logging and monitoring system events on Windows, leveraging Event Tracing for Windows (ETW). It provides real-time session tracking, rule-based alerting, and detailed event analysis.

## Description

ETW Go is designed to streamline the process of capturing and analyzing system events. It uses the `golang-etw` package to interface with Windows Event Tracing, allowing for high-performance data collection. The program includes functionality for parsing event data, applying custom rules for event handling, and generating alerts. The application leverages ETW providers to capture events of interest, parse them for specific fields specified in the configuration files, and log them to a file. The application then takes codified rules to look for attack vectors of interest from the log files.


## Getting Started

### Dependencies

- Go 1.21.4 or later
- Windows 10 or later (ETW only exists on Windows OS)
- PowerShell 5.1 or later (for BurntToast notifications).

### Installing

1. Clone the repository
```
git clone https://github.com/OhZedTee/ETW-Network-Scanner-Go.git
```

2. Download Dependencies
```
go mod tidy
```
This command cleans up the project's `go.mod` and `go.sum` files and downloads any missing dependencies.

3. Install the BurntToast Powershell Module
To receive alert notifications, the BurntToast PowerShell module must be installed. Run the following command in PowerShell to install it:
```
Install-Module -Name BurntToast

Get-ExecutionPolicy

#If Restricted, set to RemoteSigned:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Configuration
The program can be configured using `providers.yml` and `rules.yml` in the `config/` directory:
- `providers.yml`: Define the providers, events, and fields to monitor. 
    - If fields of interest are not known, `- *` can be provided to parse and output all provider fields.
- `rules.yml`: Specify the rules for alert generation and event handling.
    - The following fields are required for each rule:
        - `enabled` (true/false)
            - Defines whether or not the rule should be run 
        - `alert_threshold` (int)
            - Defines the number of hit triggers that cause an alert to be thrown
        - `files` (list of files as strings)
            -  Defines the list of provider log sources to read and alert from.
    - Currently the only codified rules are:
        - `scan_detection` (Checks if the host is being network scanned)
        - `rdp_brute_force` (Checks if the host is being RDP brute forced)
    
### Compiling the Program
Since the application only works for Windows, the build script provided at the root of the project `build.sh` will create an executable for each Windows Architecture. 

To run the build script:
```
./build.sh
```

If you wish to manually compile the program, run (from the root directory):
```
GOOS=windows GOARCH=<ARCHITECTURE(amd64|386)> go build -o build/<OUTPUT_FILE> ./cmd/
```

### Executing the Program
Run the compiled executable (from the root directory) in an administrative capacity (using an admininstrative console):
```
./build/<OUTPUT_FILE>
```

Use the `--help` flag to get command-line assistance:
```
./build/<OUTPUT_FILE> --help
```


Use the `--loglevel` flag to to specify what logs to output.
```
./build/<OUTPUT_FILE> --loglevel <Log Level(debug, info, warn, error, fatal, panic) (default "info")>
```

__Note:__ A minimum of log level info is needed to output logs from providers to log files.
All non-info level logs are outputted to the screen, where info is reserved for outputting logs from providers.

Logs from providers will be exported to the `logs/` directory

### Executing the Program Without Compiling
You can also execute the program without compiling. To do this, from the root directory of the project, run the following in an administrative console:
```
go run cmd/main.go --loglevel <Log Level(debug, info, warn, error, fatal, panic) (default "info")>
```


## Program Architecture

For a detailed view of the program's architecture, refer the diagram below: 
![Program Architecture](doc/Diagram.jpg)


## Version History
- 0.1
    - Initial Release


## Acknowledgments

- The `golang-etw` package for interfacing with ETW.
- BurntToast module for Windows notifications.