# Technical Documentation - Flow Meter C++

## Architecture Overview

The Flow Meter C++ is designed as a modular network traffic analysis tool with clear separation of concerns:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   main.cpp      │───▶│  flow_analyzer.h │───▶│ flow_analyzer.cpp│
│ (CLI Interface) │    │   (Definitions)  │    │ (Implementation)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   config.cpp    │    │   Data Structures│    │   Algorithms    │
│ (Configuration) │    │   - Flow         │    │   - Statistics  │
│                 │    │   - PacketInfo   │    │   - Feature     │
│                 │    │   - FlowFeatures │    │     Extraction  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Core Data Structures

### PacketInfo Structure
```cpp
struct PacketInfo {
    double timestamp;           // Packet timestamp
    uint32_t length;           // Total packet length
    std::string srcIp;         // Source IP address
    std::string dstIp;         // Destination IP address
    uint16_t srcPort;          // Source port
    uint16_t dstPort;          // Destination port
    uint8_t protocol;          // Protocol number (TCP=6, UDP=17, ICMP=1)
    uint32_t headerLength;     // Header length in bytes
    uint32_t payloadLength;    // Payload length in bytes
    std::map<std::string, bool> flags;  // TCP flags
    uint8_t icmpCode;          // ICMP code (if applicable)
    uint8_t icmpType;          // ICMP type (if applicable)
    uint16_t windowSize;       // TCP window size
};
```

### Flow Structure
```cpp
struct Flow {
    std::vector<PacketInfo> packets;     // All packets in flow
    std::vector<PacketInfo> fwdPackets;  // Forward direction packets
    std::vector<PacketInfo> bwdPackets;  // Backward direction packets
    double startTime;                    // Flow start timestamp
    double endTime;                      // Flow end timestamp
    uint8_t protocol;                    // Flow protocol
    std::string srcIp, dstIp;           // Flow endpoints
    uint16_t srcPort, dstPort;          // Flow ports
    
    // TCP flag counters for entire flow
    std::map<std::string, int> flags;
    
    // Directional flag counters
    std::map<std::string, int> fwdFlags;
    std::map<std::string, int> bwdFlags;
    
    // Additional TCP-specific fields
    uint16_t fwdInitWin, bwdInitWin;    // Initial window sizes
    std::map<std::string, int> retransmissions;  // Retransmission counts
};
```

### FlowFeatures Structure
Contains 89+ extracted features organized into categories:
- **Basic Information**: Flow ID, endpoints, protocol, timestamp
- **Packet Counts**: Total, forward, backward packet counts
- **Length Statistics**: Min, max, mean, std for packet lengths
- **Timing Features**: Flow duration, inter-arrival times
- **Rate Features**: Bytes/sec, packets/sec
- **TCP Features**: Flag counts, window sizes, retransmissions
- **Advanced Features**: Bulk transfer, active/idle times

## Algorithm Implementation

### Flow Identification

```cpp
std::string getFlowId(const std::string& srcIp, const std::string& dstIp,
                     uint16_t srcPort, uint16_t dstPort, uint8_t protocol) {
    // Normalize flow direction (smaller IP first)
    std::string flowTuple;
    if (srcIp < dstIp || (srcIp == dstIp && srcPort < dstPort)) {
        flowTuple = srcIp + ":" + std::to_string(srcPort) + "-" + 
                   dstIp + ":" + std::to_string(dstPort) + "-" + std::to_string(protocol);
    } else {
        flowTuple = dstIp + ":" + std::to_string(dstPort) + "-" + 
                   srcIp + ":" + std::to_string(srcPort) + "-" + std::to_string(protocol);
    }
    
    // Generate hash-based flow ID
    std::hash<std::string> hasher;
    size_t hashValue = hasher(flowTuple);
    return std::to_string(hashValue).substr(0, 16);
}
```

### Statistical Calculations

#### Basic Statistics
```cpp
Statistics calculateStatistics(const std::vector<double>& values) {
    Statistics stats;
    if (values.empty()) return stats;
    
    // Calculate min, max, total
    stats.min = *std::min_element(values.begin(), values.end());
    stats.max = *std::max_element(values.begin(), values.end());
    stats.total = std::accumulate(values.begin(), values.end(), 0.0);
    
    // Calculate mean
    stats.mean = stats.total / values.size();
    
    // Calculate standard deviation
    double variance = 0.0;
    for (double value : values) {
        variance += std::pow(value - stats.mean, 2);
    }
    stats.std = std::sqrt(variance / values.size());
    
    return stats;
}
```

#### Inter-Arrival Time (IAT) Calculation
```cpp
Statistics calculateIAT(const std::vector<PacketInfo>& packets) {
    std::vector<double> iats;
    
    for (size_t i = 1; i < packets.size(); i++) {
        double iat = packets[i].timestamp - packets[i-1].timestamp;
        iats.push_back(iat);
    }
    
    return calculateStatistics(iats);
}
```

### Advanced Feature Extraction

#### Bulk Transfer Detection
```cpp
std::pair<double, int> calculateBulkFeatures(const std::vector<PacketInfo>& packets) {
    if (packets.size() < config_.bulkThreshold) {
        return {0.0, 0};
    }
    
    double totalBytes = 0.0;
    int bulkPackets = 0;
    
    // Identify consecutive packets that form bulk transfers
    for (size_t i = 0; i < packets.size(); i++) {
        if (i + config_.bulkThreshold <= packets.size()) {
            // Check if next 'bulkThreshold' packets are consecutive
            bool isBulk = true;
            for (int j = 1; j < config_.bulkThreshold; j++) {
                double timeDiff = packets[i+j].timestamp - packets[i+j-1].timestamp;
                if (timeDiff > 1.0) {  // 1 second threshold
                    isBulk = false;
                    break;
                }
            }
            
            if (isBulk) {
                for (int j = 0; j < config_.bulkThreshold; j++) {
                    totalBytes += packets[i+j].length;
                    bulkPackets++;
                }
                i += config_.bulkThreshold - 1;  // Skip processed packets
            }
        }
    }
    
    double avgBulkBytes = bulkPackets > 0 ? totalBytes / bulkPackets : 0.0;
    return {avgBulkBytes, bulkPackets};
}
```

#### Active/Idle Time Detection
```cpp
std::pair<std::vector<double>, std::vector<double>> 
calculateActiveIdleTimes(const std::vector<PacketInfo>& packets) {
    std::vector<double> activeTimes;
    std::vector<double> idleTimes;
    
    if (packets.size() < 2) return {activeTimes, idleTimes};
    
    double activeStart = packets[0].timestamp;
    double lastPacketTime = packets[0].timestamp;
    
    for (size_t i = 1; i < packets.size(); i++) {
        double timeDiff = packets[i].timestamp - lastPacketTime;
        
        if (timeDiff > config_.activeThreshold) {
            // End of active period, start of idle period
            activeTimes.push_back(lastPacketTime - activeStart);
            idleTimes.push_back(timeDiff);
            activeStart = packets[i].timestamp;
        }
        
        lastPacketTime = packets[i].timestamp;
    }
    
    // Add final active period
    if (lastPacketTime > activeStart) {
        activeTimes.push_back(lastPacketTime - activeStart);
    }
    
    return {activeTimes, idleTimes};
}
```

#### Retransmission Detection
```cpp
int detectRetransmissions(const std::vector<PacketInfo>& packets) {
    int retransCount = 0;
    std::map<uint32_t, double> seqTimestamps;  // Sequence number -> timestamp
    
    for (const auto& packet : packets) {
        if (packet.protocol == 6) {  // TCP only
            // Extract sequence number from TCP header
            uint32_t seqNum = extractTCPSequenceNumber(packet);
            
            if (seqTimestamps.find(seqNum) != seqTimestamps.end()) {
                // Duplicate sequence number found
                double timeDiff = packet.timestamp - seqTimestamps[seqNum];
                if (timeDiff <= config_.retransWindow) {
                    retransCount++;
                }
            }
            
            seqTimestamps[seqNum] = packet.timestamp;
        }
    }
    
    return retransCount;
}
```

## Configuration System

### Configuration Modes

The system provides four predefined configuration modes, each optimized for different use cases:

#### Default Configuration
```cpp
Config getDefaultConfig() {
    Config config;
    config.bulkThreshold = 4;              // Moderate bulk detection
    config.enableBulkDetection = true;     // Enable bulk features
    config.activeThreshold = 1.0;          // 1 second active threshold
    config.enableActiveIdle = true;        // Enable active/idle analysis
    config.enableRetransDetection = true;  // Enable retransmission detection
    config.retransWindow = 0.1;            // 100ms retransmission window
    config.maxFlowPackets = 10000;         // Moderate packet limit
    config.flowTimeout = 3600;             // 1 hour flow timeout
    config.calculateVariance = true;       // Enable variance calculations
    config.detailedTiming = true;          // Enable detailed timing
    config.enhancedFlags = true;           // Enable enhanced flag analysis
    config.includeFlowId = true;           // Include flow ID in output
    config.timestampFormat = "datetime";   // Human-readable timestamps
    config.precision = 6;                  // 6 decimal places
    return config;
}
```

#### High Performance Configuration
```cpp
Config getHighPerformanceConfig() {
    Config config;
    config.bulkThreshold = 8;              // Higher threshold (less sensitive)
    config.enableBulkDetection = false;    // Disable for performance
    config.activeThreshold = 2.0;          // Less sensitive active detection
    config.enableActiveIdle = false;       // Disable for performance
    config.enableRetransDetection = false; // Disable for performance
    config.maxFlowPackets = 5000;          // Lower packet limit
    config.flowTimeout = 1800;             // 30 minute timeout
    config.calculateVariance = false;      // Disable variance (expensive)
    config.detailedTiming = false;         // Disable detailed timing
    config.enhancedFlags = false;          // Disable enhanced flags
    config.timestampFormat = "unix";       // Faster timestamp format
    config.precision = 3;                  // Lower precision
    return config;
}
```

### Configuration Validation
```cpp
bool validateConfig(const Config& config) {
    if (config.bulkThreshold < 1) {
        std::cerr << "bulk_threshold must be >= 1" << std::endl;
        return false;
    }
    
    if (config.activeThreshold <= 0) {
        std::cerr << "active_threshold must be > 0" << std::endl;
        return false;
    }
    
    if (config.retransWindow <= 0) {
        std::cerr << "retrans_window must be > 0" << std::endl;
        return false;
    }
    
    if (config.maxFlowPackets <= 0) {
        std::cerr << "max_flow_packets must be > 0" << std::endl;
        return false;
    }
    
    if (config.flowTimeout <= 0) {
        std::cerr << "flow_timeout must be > 0" << std::endl;
        return false;
    }
    
    if (config.precision < 0 || config.precision > 15) {
        std::cerr << "precision must be between 0 and 15" << std::endl;
        return false;
    }
    
    return true;
}
```

## Performance Optimization

### Memory Management

1. **Flow Limiting**: Maximum packets per flow prevents memory exhaustion
2. **Flow Timeout**: Automatic cleanup of inactive flows
3. **Efficient Containers**: Use of `std::unordered_map` for O(1) flow lookup
4. **Reserve Capacity**: Pre-allocate vector capacity when size is known

### Processing Optimization

1. **Early Termination**: Skip expensive calculations when disabled in config
2. **Batch Processing**: Process packets in batches for better cache locality
3. **Minimal Copying**: Use references and move semantics where possible
4. **Conditional Features**: Enable/disable features based on configuration

### I/O Optimization

1. **Buffered Output**: Use buffered file I/O for CSV export
2. **String Optimization**: Minimize string allocations and concatenations
3. **Precision Control**: Configurable floating-point precision

## Error Handling

### Exception Safety
```cpp
std::vector<FlowFeatures> FlowFeatureExtractor::analyzePcap(const std::string& pcapFile) {
    std::vector<FlowFeatures> features;
    
    try {
        FileSniffer sniffer(pcapFile);
        
        for (PDU& pdu : sniffer) {
            try {
                processPacket(pdu);
            } catch (const std::exception& e) {
                // Log packet processing error but continue
                std::cerr << "Warning: Error processing packet: " << e.what() << std::endl;
                continue;
            }
        }
        
        // Extract features from all flows
        for (const auto& [flowId, flow] : flows_) {
            try {
                FlowFeatures flowFeatures = extractFlowFeatures(flowId, flow);
                features.push_back(flowFeatures);
            } catch (const std::exception& e) {
                std::cerr << "Warning: Error extracting features for flow " 
                         << flowId << ": " << e.what() << std::endl;
                continue;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: Failed to process PCAP file: " << e.what() << std::endl;
        throw;
    }
    
    return features;
}
```

### Input Validation
```cpp
void validateInputs(const std::string& pcapFile, const std::string& outputFile) {
    // Check if input file exists
    if (!std::filesystem::exists(pcapFile)) {
        throw std::runtime_error("PCAP file does not exist: " + pcapFile);
    }
    
    // Check if input file is readable
    std::ifstream test(pcapFile);
    if (!test.good()) {
        throw std::runtime_error("Cannot read PCAP file: " + pcapFile);
    }
    
    // Check if output directory is writable
    std::filesystem::path outputPath(outputFile);
    std::filesystem::path outputDir = outputPath.parent_path();
    
    if (!outputDir.empty() && !std::filesystem::exists(outputDir)) {
        throw std::runtime_error("Output directory does not exist: " + outputDir.string());
    }
}
```

## Testing and Validation

### Unit Testing Framework
```cpp
// Example test structure (not implemented in current version)
class FlowAnalyzerTest {
public:
    void testFlowIdentification() {
        FlowFeatureExtractor extractor;
        std::string flowId1 = extractor.getFlowId("192.168.1.1", "10.0.0.1", 12345, 80, 6);
        std::string flowId2 = extractor.getFlowId("10.0.0.1", "192.168.1.1", 80, 12345, 6);
        assert(flowId1 == flowId2);  // Bidirectional flows should have same ID
    }
    
    void testStatisticalCalculations() {
        std::vector<double> values = {1.0, 2.0, 3.0, 4.0, 5.0};
        Statistics stats = calculateStatistics(values);
        assert(std::abs(stats.mean - 3.0) < 0.001);
        assert(std::abs(stats.std - 1.581) < 0.001);
    }
};
```

### Performance Benchmarking
```cpp
void benchmarkPerformance(const std::string& pcapFile) {
    auto start = std::chrono::high_resolution_clock::now();
    
    FlowFeatureExtractor extractor(getHighPerformanceConfig());
    std::vector<FlowFeatures> features = extractor.analyzePcap(pcapFile);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Processed " << features.size() << " flows in " 
              << duration.count() << " ms" << std::endl;
    std::cout << "Processing rate: " 
              << (features.size() * 1000.0 / duration.count()) 
              << " flows/second" << std::endl;
}
```

## Future Enhancements

### Planned Features
1. **Real-time Processing**: Live packet capture and analysis
2. **Additional Protocols**: Enhanced support for UDP, ICMP, and other protocols
3. **Machine Learning Integration**: Built-in ML model inference
4. **Distributed Processing**: Multi-threaded and distributed analysis
5. **Advanced Visualizations**: Built-in plotting and visualization tools

### Extensibility Points
1. **Custom Feature Extractors**: Plugin architecture for custom features
2. **Output Formats**: Support for JSON, Parquet, and other formats
3. **Database Integration**: Direct database export capabilities
4. **Configuration Profiles**: User-defined configuration profiles

## Dependencies and Compatibility

### Required Dependencies
- **libtins**: >= 4.0 (packet processing)
- **libpcap**: >= 1.8 (packet capture)
- **OpenSSL**: >= 1.1 (cryptographic functions)
- **zlib**: >= 1.2 (compression support)

### Compiler Requirements
- **GCC**: >= 7.0 (C++17 support)
- **Clang**: >= 5.0 (C++17 support)
- **MSVC**: >= 2017 (C++17 support)

### Platform Compatibility
- **Linux**: Primary target platform
- **WSL**: Windows Subsystem for Linux
- **macOS**: Experimental support
- **Windows**: Native support planned

## Build System

### CMake Integration (Future)
```cmake
cmake_minimum_required(VERSION 3.10)
project(FlowMeter VERSION 0.2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBTINS REQUIRED libtins)
pkg_check_modules(LIBPCAP REQUIRED libpcap)

add_executable(flow_analyzer
    main.cpp
    flow_analyzer.cpp
    config.cpp
)

target_link_libraries(flow_analyzer
    ${LIBTINS_LIBRARIES}
    ${LIBPCAP_LIBRARIES}
    pthread
)

target_include_directories(flow_analyzer PRIVATE
    ${LIBTINS_INCLUDE_DIRS}
    ${LIBPCAP_INCLUDE_DIRS}
)
```

### Makefile Integration
```makefile
CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra
LDFLAGS = -ltins -lpcap -lpthread

SOURCES = main.cpp flow_analyzer.cpp config.cpp
TARGET = flow_analyzer

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
```