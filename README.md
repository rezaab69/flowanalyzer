# Flow Meter C++ - Advanced Network Flow Analysis Tool

**Version**: 0.2.0  
**Author**: Advanced Network Analysis Team  
**License**: MIT

A high-performance C++ application for extracting network flow features from PCAP files using PcapPlusPlus. This tool analyzes network traffic and generates comprehensive flow-level statistics suitable for network analysis, intrusion detection, and machine learning applications.

## Features

### Core Capabilities
- **PCAP File Analysis**: Process network capture files to extract flow-level features
- **120+ Flow Features**: Comprehensive feature extraction including packet statistics, timing analysis, protocol-specific metrics, entropy analysis, behavioral patterns, and advanced statistical measures
- **Selective Feature Output**: Choose specific features or feature groups for customized analysis
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

#### Enhanced Features (New)
- **Forward/Backward Ratios**: Packet and byte ratios between flow directions
- **Entropy Analysis**: Payload and header entropy for randomness detection
- **Application Protocol Detection**: Automatic protocol identification and TLS feature extraction
- **Time-based Analysis**: Burstiness patterns and inter-arrival jitter measurements
- **Behavioral Features**: Direction changes, flow persistence, and idle time analysis
- **Network Context**: Internal/external traffic classification and port categorization
- **Higher-order Statistics**: Skewness and kurtosis for packet length and timing distributions

#### Feature Selection
- **Selective Output**: Choose specific features or feature groups to include/exclude
- **Predefined Feature Groups**: BASIC, TIMING, FLAGS, BULK, WINDOW, RETRANSMISSION, ICMP, STATISTICS, RATIOS, ENTROPY, PROTOCOL, BEHAVIORAL, NETWORK, HIGHER_ORDER
- **Custom Feature Sets**: Mix and match individual features and groups
- **Performance Optimization**: Reduce output size and processing time by selecting only needed features

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

#### Linux/WSL
```bash
# Ensure PcapPlusPlus is installed
# Then compile the project
g++ -std=c++17 -O3 -I/usr/local/include -o flow_analyzer main.cpp flow_analyzer.cpp config.cpp \
    -lPcap++ -lPacket++ -lCommon++ -lpcap -pthread
```

#### Windows (using WSL)
```bash
# From Windows PowerShell/Command Prompt
wsl g++ -std=c++17 -O3 -I/usr/local/include -o flow_analyzer main.cpp flow_analyzer.cpp config.cpp \
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
  --features LIST       Comma-separated list of specific features to include
  --feature-groups LIST Comma-separated list of feature groups to include
  --exclude-features LIST Comma-separated list of features to exclude
  -h, --help            Show help message and exit
```

### Feature Groups

The following predefined feature groups are available for selective output:

#### Core Feature Groups
- **BASIC**: Core flow information (Flow ID, IPs, ports, protocol, duration, packet counts)
- **TIMING**: Time-based features (IAT statistics, flow rates, timestamps)
- **FLAGS**: TCP flag analysis (SYN, ACK, FIN, RST, PSH, URG, CWR, ECE counts)
- **BULK**: Bulk transfer detection features
- **WINDOW**: TCP window size analysis
- **RETRANSMISSION**: Retransmission detection and counting
- **ICMP**: ICMP-specific features (code, type)
- **STATISTICS**: Advanced statistical features (variance, standard deviation)

#### Enhanced Feature Groups (New)
- **RATIOS**: Forward/backward packet and byte ratios, average packet rates
- **ENTROPY**: Payload and header entropy measurements for randomness analysis
- **PROTOCOL**: Application protocol detection, TLS handshake features, cipher suite information
- **BEHAVIORAL**: Direction change patterns, flow persistence, idle time characteristics
- **NETWORK**: Internal/external traffic classification, port category analysis
- **HIGHER_ORDER**: Statistical distribution measures (skewness, kurtosis) for packet lengths and timing

## New Features Implementation

This version includes significant enhancements with 30+ new features across 6 new feature groups:

### Forward/Backward Ratio Features (RATIOS)
- **Forward/Backward Packet Ratio**: Ratio of forward to backward packets
- **Forward/Backward Byte Ratio**: Ratio of forward to backward bytes
- **Average Packet Rate**: Overall packet transmission rate

### Entropy-based Features (ENTROPY)
- **Payload Entropy**: Randomness measure of packet payloads
- **Header Entropy**: Randomness measure of packet headers

### Application/Protocol Context (PROTOCOL)
- **Application Protocol**: Automatic detection of application layer protocols
- **TLS Certificate Count**: Number of certificates in TLS handshake
- **TLS Cipher Suite**: Cipher suite used in TLS connections

### Time-based Analysis (BEHAVIORAL)
- **Burstiness**: Measure of traffic burstiness patterns
- **Packet Inter-Arrival Jitter**: Variation in packet timing
- **Direction Change Count**: Number of flow direction changes
- **Average Idle Time**: Average time between active periods
- **Flow Persistence**: Measure of flow continuity

### Network Context (NETWORK)
- **Internal/External Flag**: Classification of traffic as internal or external
- **Port Category**: Categorization of ports (well-known, registered, dynamic)

### Higher-order Statistics (HIGHER_ORDER)
- **Packet Length Skewness**: Asymmetry of packet length distribution
- **Packet Length Kurtosis**: Tail heaviness of packet length distribution
- **IAT Skewness**: Asymmetry of inter-arrival time distribution
- **IAT Kurtosis**: Tail heaviness of inter-arrival time distribution

### Examples

#### Basic Usage
```bash
# Basic analysis with all features (including new 120+ features)
./flow_analyzer capture.pcap

# High-performance analysis with custom output
./flow_analyzer large_capture.pcap -o analysis_results.csv --config high_performance

# Detailed analysis with verbose output
./flow_analyzer network_traffic.pcap --config detailed_analysis --verbose

# Limit processing to first 1000 flows
./flow_analyzer traffic.pcap --max-flows 1000
```

#### Feature Selection Examples
```bash
# Extract only basic flow information
./flow_analyzer traffic.pcap --feature-groups basic

# Extract new entropy and behavioral features
./flow_analyzer traffic.pcap --feature-groups entropy,behavioral

# Extract all new enhanced features
./flow_analyzer traffic.pcap --feature-groups ratios,entropy,protocol,behavioral,network,higher_order

# Extract basic and timing features
./flow_analyzer traffic.pcap --feature-groups basic,timing

# Extract specific individual features
./flow_analyzer traffic.pcap --features "Flow ID,Src IP,Dst IP,Protocol,Flow Duration"

# Extract timing features but exclude flow duration
./flow_analyzer traffic.pcap --feature-groups timing --exclude-features "Flow Duration"

# Combine feature groups and individual features
./flow_analyzer traffic.pcap --feature-groups basic,flags --features "Flow Bytes/s,Flow Packets/s"

# Use high-performance config with custom feature selection
./flow_analyzer traffic.pcap --config high_performance --feature-groups basic,timing,flags
```
##### Feature Selection List
```
Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Total Fwd Packet,Total Bwd packets,
Total Length of Fwd Packet,Total Length of Bwd Packet,Fwd Packet Length Max,Fwd Packet Length Min,
Fwd Packet Length Mean,Fwd Packet Length Std,Bwd Packet Length Max,Bwd Packet Length Min,
Bwd Packet Length Mean,Bwd Packet Length Std,Flow Bytes/s,Flow Packets/s,Fwd Packets/s,Bwd Packets/s,
Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,
Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,
Fwd URG Flags,Bwd URG Flags,Fwd RST Flags,Bwd RST Flags,Fwd Header Length,Bwd Header Length,
Packet Length Min,Packet Length Max,Packet Length Mean,Packet Length Std,Packet Length Variance,
FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWR Flag Count,
ECE Flag Count,Down/Up Ratio,Average Packet Size,Fwd Segment Size Avg,Bwd Segment Size Avg,
Fwd Bytes/Bulk Avg,Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,Bwd Bytes/Bulk Avg,Bwd Packet/Bulk Avg,
Bwd Bulk Rate Avg,Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,
Subflow Bwd Bytes,FWD Init Win Bytes,Bwd Init Win Bytes,Fwd Act Data Pkts,Bwd Act Data Pkts,Fwd Seg Size Min,
Bwd Seg Size Min,Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,ICMP Code,
ICMP Type,Fwd TCP Retrans. Count,Bwd TCP Retrans. Count,Total TCP Retrans. Count,Total Connection Flow Time,
Fwd Bwd Packet Ratio,Fwd Bwd Byte Ratio,Average Packet Rate,Payload Entropy,Header Entropy,
Application Protocol,TLS Cert Count,TLS Session ID Length,TLS Cipher Suite,Burstiness,Packet IAT Jitter,
Direction Change Count,Average Idle Time,Flow Persistence,Internal External Flag,Port Category,
Packet Length Skewness,Packet Length Kurtosis,IAT Skewness,IAT Kurtosis
```

#### Configuration Examples
```bash
# Show current configuration
./flow_analyzer --show-config --config detailed_analysis

# Show configuration with feature selection
./flow_analyzer dummy.pcap --show-config --feature-groups basic,timing
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
| **Feature Selection** | | | | | |
| use_selective_output | false | true | false | true | Enable selective feature output |
| enabled_feature_groups | - | BASIC,TIMING | - | BASIC,TIMING,FLAGS | Active feature groups when selective output is enabled |

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

## Changelog

### Version 0.2.0 (Latest)
- **Enhanced Feature Set**: Expanded from 89 to 120+ flow features
- **New Feature Groups**: Added 6 new feature categories (RATIOS, ENTROPY, PROTOCOL, BEHAVIORAL, NETWORK, HIGHER_ORDER)
- **Advanced Analytics**: Implemented entropy analysis, behavioral pattern detection, and higher-order statistics
- **Protocol Intelligence**: Added automatic application protocol detection and TLS feature extraction
- **Network Context**: Enhanced with internal/external traffic classification and port categorization
- **Statistical Improvements**: Added skewness and kurtosis calculations for packet distributions
- **Cross-platform Support**: Improved Windows WSL compilation support

### Version 0.1.2
- Initial release with 89 core flow features
- Basic feature group selection
- PCAP file processing capabilities
- CSV output format

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For questions, issues, or feature requests, please open an issue on the project repository.

## Acknowledgments

- **PcapPlusPlus**: High-performance packet parsing library
- **libpcap**: Packet capture functionality
- Network security research community for feature definitions and best practices



