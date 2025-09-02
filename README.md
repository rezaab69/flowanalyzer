# Flow Meter C++ - Network Flow Feature Extractor

A high-performance C++ application for extracting network flow features from PCAP files using PcapPlusPlus. This tool analyzes network traffic and generates comprehensive flow-level statistics suitable for network analysis, intrusion detection, and machine learning applications.

## Features

### Core Capabilities
- **PCAP File Analysis**: Process network capture files to extract flow-level features
- **89+ Flow Features**: Comprehensive feature extraction including packet statistics, timing analysis, and protocol-specific metrics
- **Multiple Configuration Modes**: Optimized presets for different use cases
- **CSV Export**: Export extracted features to CSV format for further analysis
- **Cross-Platform**: Supports Linux with automated build scripts

### Extracted Features

#### Basic Flow Information
- Flow ID, source/destination IP and ports, protocol
- Flow duration and packet counts (forward/backward)
- Timestamp information

#### Packet Statistics
- Packet length statistics (min, max, mean, std deviation)
- Header and payload length analysis
- Packet size variance and ratios

#### Timing Analysis
- Inter-arrival time (IAT) statistics for forward and backward directions
- Flow rates (bytes/sec, packets/sec)
- Active and idle time detection

#### Protocol Features
- TCP flag analysis (FIN, SYN, RST, PSH, ACK, URG, CWR, ECE)
- Window size information
- ICMP code and type analysis
- Retransmission detection

#### Advanced Features
- Bulk transfer detection
- Subflow analysis
- Segment size statistics
- Connection flow time analysis

## Requirements

### System Dependencies
- **C++ Compiler**: GCC 7+ or Clang 6+ with C++17 support
- **CMake**: Version 3.10 or higher
- **PcapPlusPlus**: Network packet parsing library
- **libpcap**: Packet capture library
- **OpenSSL**: Cryptographic library
- **zlib**: Compression library

### Linux Package Requirements
```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake git pkg-config libpcap-dev libssl-dev zlib1g-dev

# Fedora/RHEL
sudo dnf install @development-tools cmake git pkgconfig libpcap-devel openssl-devel zlib-devel

# Arch Linux
sudo pacman -S base-devel cmake git pkgconf libpcap openssl zlib

# openSUSE
sudo zypper install -t pattern devel_basis
sudo zypper install cmake git pkg-config libpcap-devel libopenssl-devel zlib-devel
```

## Installation

### Automated Build (Linux)
```bash
# Clone or navigate to the project directory
git clone https://github.com/rezaab69/flowanalyzer
cd flowanalyzer

# Make the build script executable
chmod +x build_linux.sh

# Run the build script (will install dependencies and compile)
./build_linux.sh
```

The build script will:
1. Install system dependencies based on your Linux distribution
2. Download and build PcapPlusPlus if not already installed
3. Compile the flow analyzer application

### Manual Build
```bash
# Ensure PcapPlusPlus is installed
# Then compile the project
g++ -std=c++17 -O3 -o flow_analyzer main.cpp flow_analyzer.cpp config.cpp \
    -lPcap++ -lPacket++ -lCommon++ -lpcap -pthread
```

## Usage

### Basic Usage
```bash
# Analyze a PCAP file with default settings
./flow_analyzer traffic.pcap

# Specify output file
./flow_analyzer traffic.pcap -o results.csv

# Use verbose output
./flow_analyzer traffic.pcap --verbose
```

### Configuration Modes

#### Default Mode (Recommended)
```bash
./flow_analyzer traffic.pcap --config default
```
- Balanced feature extraction
- Standard performance
- All major features enabled

#### High Performance Mode
```bash
./flow_analyzer traffic.pcap --config high_performance
```
- Optimized for speed
- Reduced feature set
- Lower memory usage
- Suitable for large PCAP files

#### Detailed Analysis Mode
```bash
./flow_analyzer traffic.pcap --config detailed_analysis
```
- Maximum feature extraction
- Enhanced timing analysis
- Higher precision calculations
- Best for research and detailed analysis

#### Real-time Mode
```bash
./flow_analyzer traffic.pcap --config real_time
```
- Optimized for real-time processing
- Shorter flow timeouts
- Balanced performance and features

### Command Line Options

```
Usage: flow_analyzer <pcap_file> [options]

Positional arguments:
  pcap_file             Input PCAP file path

Optional arguments:
  -o, --output FILE     Output CSV file path (default: flow_features.csv)
  -c, --config MODE     Configuration mode (default|high_performance|detailed_analysis|real_time)
  -v, --verbose         Enable verbose output
  --show-config         Show configuration and exit
  --max-flows NUM       Maximum number of flows to process
  -h, --help            Show help message and exit
```

### Examples

```bash
# Basic analysis
./flow_analyzer capture.pcap

# High-performance analysis with custom output
./flow_analyzer large_capture.pcap -o analysis_results.csv --config high_performance

# Detailed analysis with verbose output
./flow_analyzer network_traffic.pcap --config detailed_analysis --verbose

# Limit processing to first 1000 flows
./flow_analyzer traffic.pcap --max-flows 1000

# Show current configuration
./flow_analyzer --show-config --config detailed_analysis
```

## Configuration

### Configuration Parameters

| Parameter | Default | High Perf | Detailed | Real-time | Description |
|-----------|---------|-----------|----------|-----------|-------------|
| bulk_threshold | 4 | 8 | 3 | 6 | Minimum packets for bulk detection |
| enable_bulk_detection | true | false | true | true | Enable bulk transfer analysis |
| active_threshold | 1.0 | 2.0 | 0.5 | 1.5 | Threshold for active time detection (seconds) |
| enable_active_idle | true | false | true | true | Enable active/idle time analysis |
| enable_retrans_detection | true | false | true | true | Enable retransmission detection |
| retrans_window | 0.1 | 0.1 | 0.05 | 0.1 | Retransmission detection window (seconds) |
| max_flow_packets | 10000 | 5000 | 50000 | 1000 | Maximum packets per flow |
| flow_timeout | 3600 | 1800 | 7200 | 300 | Flow timeout (seconds) |
| calculate_variance | true | false | true | true | Calculate packet length variance |
| detailed_timing | true | false | true | false | Enable detailed timing analysis |
| enhanced_flags | true | false | true | true | Enable enhanced TCP flag analysis |
| precision | 6 | 3 | 8 | 4 | Decimal precision for output |

## Output Format

The tool generates CSV files with the following feature categories:

### Flow Identification
- `flow_id`: Unique flow identifier
- `src_ip`, `src_port`: Source address and port
- `dst_ip`, `dst_port`: Destination address and port
- `protocol`: IP protocol number
- `timestamp`: Flow start time

### Basic Statistics
- `flow_duration`: Total flow duration
- `total_fwd_packets`, `total_bwd_packets`: Packet counts
- `total_length_fwd_packets`, `total_length_bwd_packets`: Total bytes

### Packet Length Features
- `fwd_packet_length_max/min/mean/std`: Forward direction statistics
- `bwd_packet_length_max/min/mean/std`: Backward direction statistics
- `packet_length_min/max/mean/std/variance`: Overall statistics

### Timing Features
- `flow_bytes_per_sec`, `flow_packets_per_sec`: Flow rates
- `flow_iat_mean/std/max/min`: Inter-arrival time statistics
- `fwd_iat_*`, `bwd_iat_*`: Directional IAT statistics

### Protocol Features
- `fin_flag_count`, `syn_flag_count`, etc.: TCP flag counts
- `fwd_psh_flags`, `bwd_psh_flags`, etc.: Directional flag counts
- `icmp_code`, `icmp_type`: ICMP information

### Advanced Features
- `fwd_bytes_bulk_avg`, `bwd_bytes_bulk_avg`: Bulk transfer statistics
- `active_mean/std/max/min`: Active time statistics
- `idle_mean/std/max/min`: Idle time statistics
- `fwd_tcp_retrans_count`, `bwd_tcp_retrans_count`: Retransmission counts

## Architecture

### Core Components

#### FlowFeatureExtractor Class
- Main analysis engine
- Handles PCAP file processing
- Manages flow state and feature extraction

#### Configuration System
- Flexible configuration management
- Multiple predefined modes
- Runtime parameter validation

#### Flow Management
- Bidirectional flow tracking
- Automatic flow timeout handling
- Memory-efficient packet processing

### Key Files

- `main.cpp`: Command-line interface and application entry point
- `flow_analyzer.h`: Core class definitions and data structures
- `flow_analyzer.cpp`: Feature extraction implementation
- `config.cpp`: Configuration management and validation
- `build_linux.sh`: Automated build script for Linux

## Performance Considerations

### Memory Usage
- Flows are processed incrementally to minimize memory footprint
- Configurable limits on packets per flow
- Automatic cleanup of expired flows

### Processing Speed
- Optimized packet parsing using PcapPlusPlus
- Efficient statistical calculations
- Configurable feature sets for performance tuning

### Scalability
- Suitable for large PCAP files (multi-GB)
- Linear processing time complexity
- Configurable resource limits

## Troubleshooting

### Common Issues

#### Build Errors
- Ensure all dependencies are installed
- Check C++17 compiler support
- Verify PcapPlusPlus installation

#### Runtime Errors
- Verify PCAP file exists and is readable
- Check available disk space for output files
- Ensure sufficient memory for large captures

#### Performance Issues
- Use `high_performance` configuration for large files
- Reduce `max_flow_packets` for memory constraints
- Consider processing files in smaller chunks

### Debug Options
- Use `--verbose` flag for detailed processing information
- Use `--show-config` to verify configuration settings
- Check system resources during processing

## Contributing

Contributions are welcome! Areas for improvement:
- Additional protocol support (IPv6, SCTP, etc.)
- Real-time packet capture integration
- Additional statistical features
- Performance optimizations
- Windows build support

## License

This project uses PcapPlusPlus and other open-source libraries. Please ensure compliance with their respective licenses when using this software.

## Acknowledgments

- **PcapPlusPlus**: High-performance packet parsing library
- **libpcap**: Packet capture functionality
- Network security research community for feature definitions and best practices

