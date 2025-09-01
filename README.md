# Flow Meter C++ - Network Traffic Flow Analysis Tool

A high-performance C++ network traffic flow analyzer that extracts comprehensive flow features from PCAP files using the libtins library. This tool is designed for network security analysis, traffic monitoring, and machine learning applications.

## Features

### Core Capabilities
- **PCAP File Analysis**: Process network packet capture files to extract flow-level features
- **89+ Flow Features**: Comprehensive feature extraction including timing, packet sizes, flags, and behavioral metrics
- **Multiple Configuration Modes**: Optimized presets for different use cases
- **CSV Export**: Export extracted features in CSV format for further analysis
- **Cross-Platform**: Supports Linux environments with WSL compatibility

### Extracted Features

#### Basic Flow Information
- Flow ID, source/destination IP addresses and ports
- Protocol type, timestamp, flow duration
- Packet counts (forward/backward directions)

#### Packet Statistics
- Packet length statistics (min, max, mean, standard deviation)
- Flow rates (bytes/sec, packets/sec)
- Header length analysis

#### Timing Analysis
- Inter-arrival time (IAT) statistics
- Active/idle time detection
- Flow duration metrics

#### TCP Features
- TCP flag counts (FIN, SYN, RST, PSH, ACK, URG, CWR, ECE)
- Window size analysis
- Retransmission detection
- Segment size statistics

#### Advanced Features
- Bulk transfer detection
- Subflow analysis
- ICMP code/type extraction
- Directional packet analysis

## Installation

### Prerequisites
- Linux environment (Ubuntu/Debian recommended, WSL supported)
- GCC/G++ compiler with C++17 support
- CMake (version 3.10+)
- Git
- libpcap development headers
- OpenSSL development headers
- zlib development headers

### Automated Installation (Recommended)

The project includes an automated build script that handles dependency installation:

```bash
# Make the build script executable
chmod +x build_linux.sh

# Run the build script (will install dependencies and compile)
./build_linux.sh
```

### Manual Installation

1. **Install System Dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install build-essential cmake git pkg-config libpcap-dev libssl-dev zlib1g-dev
   
   # Fedora/RHEL
   sudo dnf install @development-tools cmake git pkgconfig libpcap-devel openssl-devel zlib-devel
   
   # Arch Linux
   sudo pacman -Syu base-devel cmake git pkgconf libpcap openssl zlib
   ```

2. **Install libtins Library**:
   ```bash
   git clone https://github.com/mfontanini/libtins.git
   cd libtins
   mkdir build && cd build
   cmake .. -DLIBTINS_ENABLE_CXX11=1
   make -j$(nproc)
   sudo make install
   sudo ldconfig
   ```

3. **Compile the Flow Analyzer**:
   ```bash
   g++ -std=c++17 -O3 -o flow_analyzer main.cpp flow_analyzer.cpp config.cpp -ltins -lpcap -lpthread
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

The tool supports four predefined configuration modes:

#### 1. Default Mode (Recommended)
```bash
./flow_analyzer traffic.pcap --config default
```
- Balanced feature extraction
- Standard performance
- All major features enabled
- Suitable for most analysis tasks

#### 2. High Performance Mode
```bash
./flow_analyzer traffic.pcap --config high_performance
```
- Optimized for speed
- Reduced feature set
- Disabled computationally expensive features
- Ideal for large PCAP files

#### 3. Detailed Analysis Mode
```bash
./flow_analyzer traffic.pcap --config detailed_analysis
```
- Maximum feature extraction
- Enhanced precision
- All features enabled
- Best for research and detailed analysis

#### 4. Real-time Mode
```bash
./flow_analyzer traffic.pcap --config real_time
```
- Optimized for real-time processing
- Shorter flow timeouts
- Balanced feature set
- Suitable for live traffic analysis

### Advanced Options

```bash
# Limit the number of flows processed
./flow_analyzer traffic.pcap --max-flows 1000

# Show current configuration
./flow_analyzer --show-config

# Combine multiple options
./flow_analyzer traffic.pcap -o detailed_results.csv --config detailed_analysis --verbose
```

### Command Line Reference

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

## Output Format

The tool exports flow features to a CSV file with the following structure:

### CSV Columns (89+ features)
- **Flow Identification**: Flow ID, source/destination IPs and ports, protocol, timestamp
- **Basic Metrics**: Flow duration, packet counts, total bytes
- **Packet Length Statistics**: Min, max, mean, std deviation for forward/backward directions
- **Flow Rates**: Bytes per second, packets per second
- **Inter-arrival Times**: IAT statistics for flow and directional analysis
- **TCP Flags**: Counts for all TCP flag types
- **Header Analysis**: Header length statistics
- **Advanced Features**: Bulk transfer metrics, active/idle times, retransmission counts

### Sample Output
```csv
Flow_ID,Src_IP,Src_Port,Dst_IP,Dst_Port,Protocol,Timestamp,Flow_Duration,Total_Fwd_Packets,Total_Bwd_Packets,...
f1a2b3c4d5e6f7g8,192.168.1.100,12345,10.0.0.1,80,6,2024-01-01 10:00:00,5.234,15,12,...
```

## Configuration Details

### Configuration Parameters

| Parameter | Default | High Perf | Detailed | Real-time | Description |
|-----------|---------|-----------|----------|-----------|-------------|
| Bulk Threshold | 4 | 8 | 3 | 6 | Minimum packets for bulk detection |
| Active Threshold | 1.0s | 2.0s | 0.5s | 1.5s | Threshold for active time detection |
| Max Flow Packets | 10,000 | 5,000 | 50,000 | 1,000 | Maximum packets per flow |
| Flow Timeout | 3600s | 1800s | 7200s | 300s | Flow inactivity timeout |
| Calculate Variance | Yes | No | Yes | Yes | Enable variance calculations |
| Detailed Timing | Yes | No | Yes | No | Enhanced timing analysis |
| Retrans Detection | Yes | No | Yes | Yes | TCP retransmission detection |

## Technical Architecture

### Core Components

1. **FlowFeatureExtractor**: Main analysis engine
   - Packet processing and flow reconstruction
   - Feature extraction algorithms
   - Statistical calculations

2. **Configuration System**: Flexible configuration management
   - Predefined configuration modes
   - Parameter validation
   - Runtime configuration display

3. **Flow Management**: Efficient flow tracking
   - Bidirectional flow identification
   - Packet classification
   - Flow timeout handling

### Dependencies

- **libtins**: High-level packet crafting and sniffing library
- **libpcap**: Low-level packet capture library
- **Standard C++ Libraries**: STL containers, algorithms, I/O

### Performance Considerations

- **Memory Management**: Efficient flow storage with configurable limits
- **Processing Speed**: Optimized algorithms for large PCAP files
- **Scalability**: Configurable parameters for different use cases

## Use Cases

### Network Security
- Intrusion detection system feature extraction
- Malware traffic analysis
- Anomaly detection in network flows

### Traffic Analysis
- Network performance monitoring
- Bandwidth utilization analysis
- Application identification

### Machine Learning
- Feature engineering for ML models
- Dataset preparation for network classification
- Behavioral analysis of network traffic

### Research Applications
- Network protocol analysis
- Traffic characterization studies
- Performance evaluation

## Troubleshooting

### Common Issues

1. **libtins not found**:
   ```bash
   sudo ldconfig
   export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
   ```

2. **Permission denied for PCAP file**:
   ```bash
   chmod +r your_file.pcap
   ```

3. **Large memory usage**:
   - Use `high_performance` configuration mode
   - Reduce `--max-flows` parameter
   - Process smaller PCAP files

4. **Compilation errors**:
   - Ensure C++17 support: `g++ --version`
   - Check all dependencies are installed
   - Verify libtins installation

### WSL-Specific Notes

- Ensure WSL2 is being used for better performance
- Install dependencies within the WSL environment
- PCAP files should be accessible from within WSL

## Contributing

Contributions are welcome! Areas for improvement:
- Additional feature extraction algorithms
- Performance optimizations
- Support for additional output formats
- Real-time processing capabilities

## License

This project is provided as-is for educational and research purposes.

## Version Information

- **Version**: 0.2
- **Build Target**: Linux/WSL
- **C++ Standard**: C++17
- **Primary Dependency**: libtins