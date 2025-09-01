# API Reference - Flow Meter C++

## Table of Contents
- [Core Classes](#core-classes)
- [Data Structures](#data-structures)
- [Configuration Functions](#configuration-functions)
- [Utility Functions](#utility-functions)
- [Constants and Enumerations](#constants-and-enumerations)
- [Error Handling](#error-handling)

## Core Classes

### FlowFeatureExtractor

The main class responsible for extracting flow features from PCAP files.

#### Constructor
```cpp
explicit FlowFeatureExtractor(const Config& config = Config())
```
**Parameters:**
- `config`: Configuration object specifying analysis parameters

**Description:**
Initializes the feature extractor with the provided configuration. If no configuration is provided, uses default settings.

#### Public Methods

##### analyzePcap
```cpp
std::vector<FlowFeatures> analyzePcap(const std::string& pcapFile)
```
**Parameters:**
- `pcapFile`: Path to the PCAP file to analyze

**Returns:**
- Vector of `FlowFeatures` objects containing extracted features for each flow

**Throws:**
- `std::runtime_error`: If file cannot be opened or processed
- `std::invalid_argument`: If file format is invalid

**Description:**
Analyzes the specified PCAP file and extracts flow features. This is the main entry point for flow analysis.

##### exportToCSV
```cpp
void exportToCSV(const std::vector<FlowFeatures>& features, const std::string& outputFile)
```
**Parameters:**
- `features`: Vector of flow features to export
- `outputFile`: Path to the output CSV file

**Throws:**
- `std::runtime_error`: If output file cannot be created or written

**Description:**
Exports the extracted flow features to a CSV file with appropriate headers and formatting.

##### processPacket
```cpp
void processPacket(const PDU& pdu)
```
**Parameters:**
- `pdu`: Packet Data Unit from libtins

**Description:**
Processes a single packet and updates internal flow state. This method is called internally by `analyzePcap` but can be used for custom packet processing workflows.

##### extractFlowFeatures
```cpp
FlowFeatures extractFlowFeatures(const std::string& flowId, const Flow& flow)
```
**Parameters:**
- `flowId`: Unique identifier for the flow
- `flow`: Flow object containing packet information

**Returns:**
- `FlowFeatures` object with all extracted features

**Description:**
Extracts comprehensive features from a single flow. This method performs all statistical calculations and feature engineering.

#### Private Methods

##### getFlowId
```cpp
std::string getFlowId(const std::string& srcIp, const std::string& dstIp,
                     uint16_t srcPort, uint16_t dstPort, uint8_t protocol)
```
**Parameters:**
- `srcIp`: Source IP address
- `dstIp`: Destination IP address
- `srcPort`: Source port number
- `dstPort`: Destination port number
- `protocol`: Protocol number (6=TCP, 17=UDP, 1=ICMP)

**Returns:**
- String representing unique flow identifier

**Description:**
Generates a unique flow identifier by normalizing the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol). Ensures bidirectional flows have the same ID.

##### isForwardDirection
```cpp
bool isForwardDirection(const std::string& srcIp, const std::string& dstIp,
                       uint16_t srcPort, uint16_t dstPort,
                       const std::string& flowSrcIp, uint16_t flowSrcPort)
```
**Parameters:**
- `srcIp`, `dstIp`: Packet source and destination IPs
- `srcPort`, `dstPort`: Packet source and destination ports
- `flowSrcIp`, `flowSrcPort`: Flow's canonical source IP and port

**Returns:**
- `true` if packet is in forward direction, `false` for backward

**Description:**
Determines packet direction within a bidirectional flow based on the canonical flow direction.

##### extractPacketInfo
```cpp
PacketInfo extractPacketInfo(const PDU& pdu)
```
**Parameters:**
- `pdu`: Packet Data Unit from libtins

**Returns:**
- `PacketInfo` structure with extracted packet details

**Description:**
Extracts relevant information from a packet including headers, flags, and payload information.

##### calculateStatistics
```cpp
Statistics calculateStatistics(const std::vector<double>& values)
```
**Parameters:**
- `values`: Vector of numerical values

**Returns:**
- `Statistics` structure with min, max, mean, std, and total

**Description:**
Calculates basic statistical measures for a set of values.

##### calculateIAT
```cpp
Statistics calculateIAT(const std::vector<PacketInfo>& packets)
```
**Parameters:**
- `packets`: Vector of packets in chronological order

**Returns:**
- `Statistics` structure for inter-arrival times

**Description:**
Calculates inter-arrival time statistics between consecutive packets.

##### calculateBulkFeatures
```cpp
std::pair<double, int> calculateBulkFeatures(const std::vector<PacketInfo>& packets)
```
**Parameters:**
- `packets`: Vector of packets to analyze

**Returns:**
- Pair containing average bulk bytes and bulk packet count

**Description:**
Detects and quantifies bulk transfer characteristics in packet sequences.

##### calculateActiveIdleTimes
```cpp
std::pair<std::vector<double>, std::vector<double>> 
calculateActiveIdleTimes(const std::vector<PacketInfo>& packets)
```
**Parameters:**
- `packets`: Vector of packets in chronological order

**Returns:**
- Pair of vectors containing active times and idle times

**Description:**
Identifies active and idle periods in the flow based on packet timing.

##### detectRetransmissions
```cpp
int detectRetransmissions(const std::vector<PacketInfo>& packets)
```
**Parameters:**
- `packets`: Vector of TCP packets

**Returns:**
- Number of detected retransmissions

**Description:**
Detects TCP retransmissions based on duplicate sequence numbers within a time window.

## Data Structures

### Config

Configuration structure controlling feature extraction behavior.

```cpp
struct Config {
    // Bulk transfer detection settings
    int bulkThreshold = 4;              // Minimum packets for bulk detection
    bool enableBulkDetection = true;    // Enable bulk transfer analysis
    
    // Active/Idle time detection settings
    double activeThreshold = 1.0;       // Threshold for active time (seconds)
    bool enableActiveIdle = true;       // Enable active/idle analysis
    
    // Retransmission detection settings
    bool enableRetransDetection = true; // Enable retransmission detection
    double retransWindow = 0.1;         // Retransmission time window (seconds)
    
    // Performance settings
    int maxFlowPackets = 10000;         // Maximum packets per flow
    int flowTimeout = 3600;             // Flow timeout (seconds)
    
    // Feature calculation settings
    bool calculateVariance = true;      // Enable variance calculations
    bool detailedTiming = true;         // Enable detailed timing analysis
    bool enhancedFlags = true;          // Enable enhanced flag analysis
    
    // Output settings
    bool includeFlowId = true;          // Include flow ID in output
    std::string timestampFormat = "datetime"; // Timestamp format ("datetime" or "unix")
    int precision = 6;                  // Decimal precision for output
};
```

### PacketInfo

Structure containing extracted information from a single packet.

```cpp
struct PacketInfo {
    double timestamp = 0.0;             // Packet timestamp (seconds since epoch)
    uint32_t length = 0;                // Total packet length (bytes)
    std::string srcIp;                  // Source IP address
    std::string dstIp;                  // Destination IP address
    uint16_t srcPort = 0;               // Source port number
    uint16_t dstPort = 0;               // Destination port number
    uint8_t protocol = 0;               // Protocol number
    uint32_t headerLength = 0;          // Header length (bytes)
    uint32_t payloadLength = 0;         // Payload length (bytes)
    std::map<std::string, bool> flags;  // TCP flags ("SYN", "ACK", etc.)
    uint8_t icmpCode = 0;               // ICMP code (if applicable)
    uint8_t icmpType = 0;               // ICMP type (if applicable)
    uint16_t windowSize = 0;            // TCP window size
};
```

### Flow

Structure representing a network flow with all associated packets.

```cpp
struct Flow {
    std::vector<PacketInfo> packets;     // All packets in flow
    std::vector<PacketInfo> fwdPackets;  // Forward direction packets
    std::vector<PacketInfo> bwdPackets;  // Backward direction packets
    double startTime = 0.0;              // Flow start timestamp
    double endTime = 0.0;                // Flow end timestamp
    uint8_t protocol = 0;                // Flow protocol
    std::string srcIp;                   // Flow source IP
    std::string dstIp;                   // Flow destination IP
    uint16_t srcPort = 0;                // Flow source port
    uint16_t dstPort = 0;                // Flow destination port
    
    // TCP flags counters
    std::map<std::string, int> flags = {
        {"FIN", 0}, {"SYN", 0}, {"RST", 0}, {"PSH", 0},
        {"ACK", 0}, {"URG", 0}, {"CWR", 0}, {"ECE", 0}
    };
    
    std::map<std::string, int> fwdFlags = {
        {"PSH", 0}, {"URG", 0}, {"RST", 0}
    };
    
    std::map<std::string, int> bwdFlags = {
        {"PSH", 0}, {"URG", 0}, {"RST", 0}
    };
    
    uint8_t icmpCode = 0;                // ICMP code
    uint8_t icmpType = 0;                // ICMP type
    uint16_t fwdInitWin = 0;             // Forward initial window size
    uint16_t bwdInitWin = 0;             // Backward initial window size
    
    std::map<std::string, int> retransmissions = {
        {"fwd", 0}, {"bwd", 0}
    };
};
```

### Statistics

Structure containing basic statistical measures.

```cpp
struct Statistics {
    double min = 0.0;     // Minimum value
    double max = 0.0;     // Maximum value
    double mean = 0.0;    // Arithmetic mean
    double std = 0.0;     // Standard deviation
    double total = 0.0;   // Sum of all values
};
```

### FlowFeatures

Structure containing all extracted flow features (89+ features).

```cpp
struct FlowFeatures {
    // Basic flow information
    std::string flowId;                  // Unique flow identifier
    std::string srcIp;                   // Source IP address
    uint16_t srcPort;                    // Source port
    std::string dstIp;                   // Destination IP address
    uint16_t dstPort;                    // Destination port
    uint8_t protocol;                    // Protocol number
    std::string timestamp;               // Flow start timestamp
    
    // Flow duration and packet counts
    double flowDuration;                 // Total flow duration (seconds)
    int totalFwdPackets;                 // Forward packet count
    int totalBwdPackets;                 // Backward packet count
    
    // Packet length statistics
    double totalLengthFwdPackets;        // Total forward bytes
    double totalLengthBwdPackets;        // Total backward bytes
    double fwdPacketLengthMax;           // Forward max packet length
    double fwdPacketLengthMin;           // Forward min packet length
    double fwdPacketLengthMean;          // Forward mean packet length
    double fwdPacketLengthStd;           // Forward packet length std dev
    double bwdPacketLengthMax;           // Backward max packet length
    double bwdPacketLengthMin;           // Backward min packet length
    double bwdPacketLengthMean;          // Backward mean packet length
    double bwdPacketLengthStd;           // Backward packet length std dev
    
    // Flow rates
    double flowBytesPerSec;              // Flow bytes per second
    double flowPacketsPerSec;            // Flow packets per second
    double fwdPacketsPerSec;             // Forward packets per second
    double bwdPacketsPerSec;             // Backward packets per second
    
    // Inter-arrival times
    double flowIATMean;                  // Flow IAT mean
    double flowIATStd;                   // Flow IAT standard deviation
    double flowIATMax;                   // Flow IAT maximum
    double flowIATMin;                   // Flow IAT minimum
    double fwdIATTotal;                  // Forward IAT total
    double fwdIATMean;                   // Forward IAT mean
    double fwdIATStd;                    // Forward IAT standard deviation
    double fwdIATMax;                    // Forward IAT maximum
    double fwdIATMin;                    // Forward IAT minimum
    double bwdIATTotal;                  // Backward IAT total
    double bwdIATMean;                   // Backward IAT mean
    double bwdIATStd;                    // Backward IAT standard deviation
    double bwdIATMax;                    // Backward IAT maximum
    double bwdIATMin;                    // Backward IAT minimum
    
    // TCP Flags
    int fwdPSHFlags;                     // Forward PSH flag count
    int bwdPSHFlags;                     // Backward PSH flag count
    int fwdURGFlags;                     // Forward URG flag count
    int bwdURGFlags;                     // Backward URG flag count
    int fwdRSTFlags;                     // Forward RST flag count
    int bwdRSTFlags;                     // Backward RST flag count
    
    // Header lengths
    double fwdHeaderLength;              // Forward header length
    double bwdHeaderLength;              // Backward header length
    
    // Packet statistics
    double packetLengthMin;              // Overall min packet length
    double packetLengthMax;              // Overall max packet length
    double packetLengthMean;             // Overall mean packet length
    double packetLengthStd;              // Overall packet length std dev
    double packetLengthVariance;         // Overall packet length variance
    
    // Flag counts
    int finFlagCount;                    // FIN flag count
    int synFlagCount;                    // SYN flag count
    int rstFlagCount;                    // RST flag count
    int pshFlagCount;                    // PSH flag count
    int ackFlagCount;                    // ACK flag count
    int urgFlagCount;                    // URG flag count
    int cwrFlagCount;                    // CWR flag count
    int eceFlagCount;                    // ECE flag count
    
    // Ratios and averages
    double downUpRatio;                  // Download/upload ratio
    double averagePacketSize;            // Average packet size
    
    // Segment sizes
    double fwdSegmentSizeAvg;            // Forward average segment size
    double bwdSegmentSizeAvg;            // Backward average segment size
    
    // Bulk transfer features
    double fwdBytesBulkAvg;              // Forward bulk bytes average
    double fwdPacketBulkAvg;             // Forward bulk packets average
    double fwdBulkRateAvg;               // Forward bulk rate average
    double bwdBytesBulkAvg;              // Backward bulk bytes average
    double bwdPacketBulkAvg;             // Backward bulk packets average
    double bwdBulkRateAvg;               // Backward bulk rate average
    
    // Subflow features
    int subflowFwdPackets;               // Subflow forward packets
    double subflowFwdBytes;              // Subflow forward bytes
    int subflowBwdPackets;               // Subflow backward packets
    double subflowBwdBytes;              // Subflow backward bytes
    
    // Window sizes
    uint16_t fwdInitWinBytes;            // Forward initial window size
    uint16_t bwdInitWinBytes;            // Backward initial window size
    
    // Active data packets
    int fwdActDataPkts;                  // Forward active data packets
    int bwdActDataPkts;                  // Backward active data packets
    
    // Minimum segment sizes
    double fwdSegSizeMin;                // Forward minimum segment size
    double bwdSegSizeMin;                // Backward minimum segment size
    
    // Active/Idle times
    double activeMean;                   // Active time mean
    double activeStd;                    // Active time standard deviation
    double activeMax;                    // Active time maximum
    double activeMin;                    // Active time minimum
    double idleMean;                     // Idle time mean
    double idleStd;                      // Idle time standard deviation
    double idleMax;                      // Idle time maximum
    double idleMin;                      // Idle time minimum
    
    // ICMP features
    uint8_t icmpCode;                    // ICMP code
    uint8_t icmpType;                    // ICMP type
    
    // Retransmission counts
    int fwdTCPRetransCount;              // Forward TCP retransmissions
    int bwdTCPRetransCount;              // Backward TCP retransmissions
    int totalTCPRetransCount;            // Total TCP retransmissions
    
    // Total connection flow time
    double totalConnectionFlowTime;      // Total connection time
};
```

## Configuration Functions

### getDefaultConfig
```cpp
Config getDefaultConfig()
```
**Returns:**
- Default configuration suitable for general use

**Description:**
Returns a balanced configuration with all features enabled and moderate performance settings.

### getHighPerformanceConfig
```cpp
Config getHighPerformanceConfig()
```
**Returns:**
- High-performance configuration optimized for speed

**Description:**
Returns a configuration optimized for processing large PCAP files quickly by disabling computationally expensive features.

### getDetailedAnalysisConfig
```cpp
Config getDetailedAnalysisConfig()
```
**Returns:**
- Detailed analysis configuration with maximum features

**Description:**
Returns a configuration that enables all features and uses the highest precision settings for comprehensive analysis.

### getRealTimeConfig
```cpp
Config getRealTimeConfig()
```
**Returns:**
- Real-time processing configuration

**Description:**
Returns a configuration optimized for real-time or near-real-time processing with shorter timeouts and balanced features.

### getConfig
```cpp
Config getConfig(const std::string& configName)
```
**Parameters:**
- `configName`: Configuration mode name ("default", "high_performance", "detailed_analysis", "real_time")

**Returns:**
- Configuration object for the specified mode

**Description:**
Factory function that returns the appropriate configuration based on the mode name.

### validateConfig
```cpp
bool validateConfig(const Config& config)
```
**Parameters:**
- `config`: Configuration object to validate

**Returns:**
- `true` if configuration is valid, `false` otherwise

**Description:**
Validates configuration parameters and prints error messages for invalid values.

### printConfig
```cpp
void printConfig(const Config& config)
```
**Parameters:**
- `config`: Configuration object to display

**Description:**
Prints the configuration parameters in a human-readable format.

## Utility Functions

### Command Line Parsing

#### parseArguments
```cpp
Arguments parseArguments(int argc, char* argv[])
```
**Parameters:**
- `argc`: Argument count
- `argv`: Argument vector

**Returns:**
- `Arguments` structure with parsed command line options

**Description:**
Parses command line arguments and returns a structured representation.

#### printUsage
```cpp
void printUsage(const char* programName)
```
**Parameters:**
- `programName`: Name of the program executable

**Description:**
Prints comprehensive usage information including all available options and examples.

### Arguments Structure
```cpp
struct Arguments {
    std::string pcapFile;                // Input PCAP file path
    std::string outputFile = "flow_features.csv"; // Output CSV file path
    std::string configMode = "default";  // Configuration mode
    bool verbose = false;                // Verbose output flag
    bool showConfig = false;             // Show configuration flag
    int maxFlows = -1;                   // Maximum flows to process
    bool help = false;                   // Help flag
};
```

## Constants and Enumerations

### Protocol Numbers
```cpp
const uint8_t PROTOCOL_ICMP = 1;   // ICMP protocol
const uint8_t PROTOCOL_TCP = 6;    // TCP protocol
const uint8_t PROTOCOL_UDP = 17;   // UDP protocol
```

### TCP Flags
```cpp
const std::vector<std::string> TCP_FLAGS = {
    "FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWR", "ECE"
};
```

### Default Values
```cpp
const int DEFAULT_BULK_THRESHOLD = 4;
const double DEFAULT_ACTIVE_THRESHOLD = 1.0;
const double DEFAULT_RETRANS_WINDOW = 0.1;
const int DEFAULT_MAX_FLOW_PACKETS = 10000;
const int DEFAULT_FLOW_TIMEOUT = 3600;
const int DEFAULT_PRECISION = 6;
```

## Error Handling

### Exception Types

The library uses standard C++ exceptions:

- `std::runtime_error`: For runtime errors like file I/O issues
- `std::invalid_argument`: For invalid input parameters
- `std::out_of_range`: For array/vector access errors
- `std::bad_alloc`: For memory allocation failures

### Error Codes

```cpp
enum class ErrorCode {
    SUCCESS = 0,
    FILE_NOT_FOUND = 1,
    INVALID_FORMAT = 2,
    MEMORY_ERROR = 3,
    CONFIGURATION_ERROR = 4,
    PROCESSING_ERROR = 5
};
```

### Error Handling Best Practices

1. **Always check return values** for functions that can fail
2. **Use try-catch blocks** around file operations and packet processing
3. **Validate inputs** before processing
4. **Handle partial failures** gracefully (e.g., skip problematic packets)
5. **Provide meaningful error messages** with context

### Example Error Handling

```cpp
try {
    FlowFeatureExtractor extractor(config);
    std::vector<FlowFeatures> features = extractor.analyzePcap("traffic.pcap");
    extractor.exportToCSV(features, "output.csv");
} catch (const std::runtime_error& e) {
    std::cerr << "Runtime error: " << e.what() << std::endl;
    return 1;
} catch (const std::invalid_argument& e) {
    std::cerr << "Invalid argument: " << e.what() << std::endl;
    return 2;
} catch (const std::exception& e) {
    std::cerr << "Unexpected error: " << e.what() << std::endl;
    return 3;
}
```

## Thread Safety

### Thread Safety Considerations

- **FlowFeatureExtractor**: Not thread-safe. Create separate instances for concurrent processing.
- **Configuration objects**: Thread-safe for read operations after initialization.
- **Static functions**: Thread-safe (getConfig, validateConfig, etc.).

### Concurrent Processing Example

```cpp
#include <thread>
#include <vector>
#include <future>

std::vector<std::future<std::vector<FlowFeatures>>> futures;

for (const auto& pcapFile : pcapFiles) {
    futures.push_back(std::async(std::launch::async, [pcapFile, config]() {
        FlowFeatureExtractor extractor(config);
        return extractor.analyzePcap(pcapFile);
    }));
}

// Collect results
for (auto& future : futures) {
    auto features = future.get();
    // Process features...
}
```

## Memory Management

### Memory Usage Guidelines

1. **Flow Limits**: Use `maxFlowPackets` to limit memory per flow
2. **Flow Timeout**: Use `flowTimeout` to automatically clean up old flows
3. **Batch Processing**: Process large PCAP files in chunks if memory is limited
4. **Configuration**: Use `high_performance` mode for memory-constrained environments

### Memory Estimation

```cpp
// Rough memory estimation per flow
size_t estimateFlowMemory(int maxPackets) {
    size_t packetInfoSize = sizeof(PacketInfo);
    size_t flowOverhead = sizeof(Flow);
    return flowOverhead + (packetInfoSize * maxPackets * 3); // packets + fwd + bwd
}

// Total memory estimation
size_t estimateTotalMemory(int maxFlows, int maxPacketsPerFlow) {
    return maxFlows * estimateFlowMemory(maxPacketsPerFlow);
}
```