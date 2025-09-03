#ifndef FLOW_ANALYZER_H
#define FLOW_ANALYZER_H

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <cstdint>
#include <deque>
#include <PcapPlusPlus/Packet.h>
#include <PcapPlusPlus/IPv4Layer.h>
#include <PcapPlusPlus/TcpLayer.h>
#include <PcapPlusPlus/UdpLayer.h>
#include <PcapPlusPlus/IcmpLayer.h>
#include <PcapPlusPlus/PcapFileDevice.h>
#include <PcapPlusPlus/PcapLiveDevice.h>

// Configuration structure
struct Config {
    // Bulk transfer detection settings
    int bulkThreshold = 4;
    bool enableBulkDetection = true;
    
    // Active/Idle time detection settings
    double activeThreshold = 1.0;
    bool enableActiveIdle = true;
    
    // Retransmission detection settings
    bool enableRetransDetection = true;
    double retransWindow = 0.1;
    
    // Performance settings
    int maxFlowPackets = 10000;
    int flowTimeout = 3600;
    
    // Feature calculation settings
    bool calculateVariance = true;
    bool detailedTiming = true;
    bool enhancedFlags = true;
    
    // Output settings
    bool includeFlowId = true;
    std::string timestampFormat = "datetime";
    int precision = 6;
    bool verbose = false;
    
    // Streaming processing settings
    bool enableStreaming = false;     // Process packets without storing them
    int streamingBufferSize = 100;    // Number of packets to buffer for statistics
    bool streamingRealTime = true;    // Extract features in real-time
    
    // Feature selection settings
    std::set<std::string> enabledFeatureGroups = {"all"}; // Feature groups to include
    std::set<std::string> enabledFeatures = {};           // Individual features to include (overrides groups)
    std::set<std::string> disabledFeatures = {};          // Individual features to exclude
    bool useSelectiveOutput = false;                      // Enable selective feature output
};

// Feature group definitions
struct FeatureGroups {
    static const std::set<std::string> BASIC;
    static const std::set<std::string> TIMING;
    static const std::set<std::string> FLAGS;
    static const std::set<std::string> BULK;
    static const std::set<std::string> WINDOW;
    static const std::set<std::string> RETRANSMISSION;
    static const std::set<std::string> ICMP;
    static const std::set<std::string> STATISTICS;
    static const std::set<std::string> RATIOS;
    static const std::set<std::string> ENTROPY;
    static const std::set<std::string> PROTOCOL;
    static const std::set<std::string> BEHAVIORAL;
    static const std::set<std::string> NETWORK;
    static const std::set<std::string> HIGHER_ORDER;
    static const std::set<std::string> ALL;
    
    static std::set<std::string> getFeaturesByGroup(const std::string& groupName);
    static std::set<std::string> getAllFeatureNames();
    static bool isValidFeatureName(const std::string& featureName);
    static bool isValidGroupName(const std::string& groupName);
};

// Optimized packet information structure
struct PacketInfo {
    double timestamp = 0.0;
    uint16_t length = 0;           // Reduced from uint32_t (max 65535 bytes)
    uint32_t srcIpHash = 0;        // Hash of source IP instead of string
    uint32_t dstIpHash = 0;        // Hash of destination IP instead of string
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t protocol = 0;
    uint16_t headerLength = 0;     // Reduced from uint32_t
    uint16_t payloadLength = 0;    // Reduced from uint32_t
    
    // TCP flags as bit fields (1 byte total)
    struct {
        uint8_t fin : 1;
        uint8_t syn : 1;
        uint8_t rst : 1;
        uint8_t psh : 1;
        uint8_t ack : 1;
        uint8_t urg : 1;
        uint8_t cwr : 1;
        uint8_t ece : 1;
    } tcpFlags;
    
    uint8_t icmpCode = 0;
    uint8_t icmpType = 0;
    uint16_t windowSize = 0;
    
    // Keep original IP strings for feature extraction (only when needed)
    std::string srcIp;
    std::string dstIp;
    std::map<std::string, bool> flags; // Keep for compatibility
};

// Flow structure with optimized packet storage
struct Flow {
    std::vector<PacketInfo> packets;
    std::vector<bool> isForward; // Direction flag for each packet (true = forward, false = backward)
    double startTime = 0.0;
    double endTime = 0.0;
    uint8_t protocol = 0;
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    
    // Cached counts for performance
    size_t fwdPacketCount = 0;
    size_t bwdPacketCount = 0;
    
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
    
    uint8_t icmpCode = 0;
    uint8_t icmpType = 0;
    uint16_t fwdInitWin = 0;
    uint16_t bwdInitWin = 0;
    
    std::map<std::string, int> retransmissions = {
        {"fwd", 0}, {"bwd", 0}
    };
};

// Streaming flow structure for memory-efficient processing
struct StreamingFlow {
    // Basic flow info
    double startTime = 0.0;
    double endTime = 0.0;
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t protocol = 0;
    
    // Packet statistics (no packet storage)
    uint32_t fwdPacketCount = 0;
    uint32_t bwdPacketCount = 0;
    uint64_t fwdTotalBytes = 0;
    uint64_t bwdTotalBytes = 0;
    uint32_t fwdHeaderBytes = 0;
    uint32_t bwdHeaderBytes = 0;
    
    // Length statistics
    uint16_t fwdMinLength = UINT16_MAX;
    uint16_t fwdMaxLength = 0;
    uint16_t bwdMinLength = UINT16_MAX;
    uint16_t bwdMaxLength = 0;
    double fwdLengthSum = 0.0;
    double bwdLengthSum = 0.0;
    double fwdLengthSumSquares = 0.0;
    double bwdLengthSumSquares = 0.0;
    
    // Timing statistics
    double lastFwdTime = 0.0;
    double lastBwdTime = 0.0;
    std::vector<double> fwdInterArrivalTimes;
    std::vector<double> bwdInterArrivalTimes;
    
    // TCP flags counters
    uint32_t fwdPshFlags = 0;
    uint32_t bwdPshFlags = 0;
    uint32_t fwdUrgFlags = 0;
    uint32_t bwdUrgFlags = 0;
    
    // Window size statistics
    uint32_t fwdWindowSizeSum = 0;
    uint32_t bwdWindowSizeSum = 0;
    
    // Limited packet buffer for advanced statistics
    std::deque<PacketInfo> recentPackets;
    std::deque<bool> recentIsForward;
};

// Statistics structure
struct Statistics {
    double min = 0.0;
    double max = 0.0;
    double mean = 0.0;
    double std = 0.0;
    double total = 0.0;
};

// Flow features structure (89+ features)
struct FlowFeatures {
    // Basic flow information
    std::string flowId;
    std::string srcIp;
    uint16_t srcPort;
    std::string dstIp;
    uint16_t dstPort;
    uint8_t protocol;
    std::string timestamp;
    
    // Flow duration and packet counts
    double flowDuration;
    int totalFwdPackets;
    int totalBwdPackets;
    uint32_t fwdPacketCount;
    uint32_t bwdPacketCount;
    uint64_t fwdTotalBytes;
    uint64_t bwdTotalBytes;
    
    // Packet lengths
    double totalLengthFwdPackets;
    double totalLengthBwdPackets;
    double fwdPacketLengthMax;
    double fwdPacketLengthMin;
    double fwdPacketLengthMean;
    double fwdPacketLengthStd;
    double bwdPacketLengthMax;
    double bwdPacketLengthMin;
    double bwdPacketLengthMean;
    double bwdPacketLengthStd;
    
    // Flow rates
    double flowBytesPerSec;
    double flowPacketsPerSec;
    double fwdPacketsPerSec;
    double bwdPacketsPerSec;
    
    // Inter-arrival times
    double flowIATMean;
    double flowIATStd;
    double flowIATMax;
    double flowIATMin;
    double fwdIATTotal;
    double fwdIATMean;
    double fwdIATStd;
    double fwdIATMax;
    double fwdIATMin;
    double bwdIATTotal;
    double bwdIATMean;
    double bwdIATStd;
    double bwdIATMax;
    double bwdIATMin;
    
    // TCP flags
    int fwdPSHFlags;
    int bwdPSHFlags;
    int fwdURGFlags;
    int bwdURGFlags;
    int fwdRSTFlags;
    int bwdRSTFlags;
    uint32_t fwdPshFlags;
    uint32_t bwdPshFlags;
    uint32_t fwdUrgFlags;
    uint32_t bwdUrgFlags;
    
    // Header lengths
    double fwdHeaderLength;
    double bwdHeaderLength;
    
    // Packet statistics
    double packetLengthMin;
    double packetLengthMax;
    double packetLengthMean;
    double packetLengthStd;
    double packetLengthVariance;
    
    // Flag counts
    int finFlagCount;
    int synFlagCount;
    int rstFlagCount;
    int pshFlagCount;
    int ackFlagCount;
    int urgFlagCount;
    int cwrFlagCount;
    int eceFlagCount;
    
    // Ratios and averages
    double downUpRatio;
    double averagePacketSize;
    
    // Segment sizes
    double fwdSegmentSizeAvg;
    double bwdSegmentSizeAvg;
    
    // Bulk transfer features
    double fwdBytesBulkAvg;
    double fwdPacketBulkAvg;
    double fwdBulkRateAvg;
    double bwdBytesBulkAvg;
    double bwdPacketBulkAvg;
    double bwdBulkRateAvg;
    
    // Subflow features
    int subflowFwdPackets;
    double subflowFwdBytes;
    int subflowBwdPackets;
    double subflowBwdBytes;
    
    // Window sizes
    uint16_t fwdInitWinBytes;
    uint16_t bwdInitWinBytes;
    
    // Active data packets
    int fwdActDataPkts;
    int bwdActDataPkts;
    
    // Minimum segment sizes
    double fwdSegSizeMin;
    double bwdSegSizeMin;
    
    // Active/Idle times
    double activeMean;
    double activeStd;
    double activeMax;
    double activeMin;
    double idleMean;
    double idleStd;
    double idleMax;
    double idleMin;
    
    // ICMP features
    uint8_t icmpCode;
    uint8_t icmpType;
    
    // Retransmission counts
    int fwdTCPRetransCount;
    int bwdTCPRetransCount;
    int totalTCPRetransCount;
    
    // Connection flow time
    double totalConnectionFlowTime;
    
    // Forward/Backward ratio features
    double fwdBwdPacketRatio;
    double fwdBwdByteRatio;
    double averagePacketRate;
    
    // Entropy-based features
    double payloadEntropy;
    double headerEntropy;
    
    // Application/Protocol context features
    std::string applicationProtocol;
    int tlsCertificateCount;
    int tlsSessionIdLength;
    std::string tlsCipherSuite;
    
    // Time-based features
    double burstiness;
    double packetInterArrivalJitter;
    
    // Behavioral features
    int directionChangeCount;
    double averageIdleTime;
    double flowPersistence;
    
    // Network context features
    bool isInternalExternal; // true = internal, false = external
    std::string portCategory; // "well-known", "registered", "dynamic"
    
    // Higher-order statistics
    double packetLengthSkewness;
    double packetLengthKurtosis;
    double iatSkewness;
    double iatKurtosis;
};

// Main flow feature extractor class
class FlowFeatureExtractor {
public:
    explicit FlowFeatureExtractor(const Config& config = Config());
    
    // Main analysis functions
    std::vector<FlowFeatures> analyzePcap(const std::string& pcapFile);
    void exportToCSV(const std::vector<FlowFeatures>& features, const std::string& outputFile);
    void exportSelectiveCSV(const std::vector<FlowFeatures>& features, const std::string& outputFile, 
                           const std::set<std::string>& selectedFeatures);
    
    // Packet processing
    void processPacket(pcpp::Packet& packet);
    
    // Feature extraction
    FlowFeatures extractFlowFeatures(const uint64_t& flowId, const Flow& flow);
    
private:
    Config config_;
    std::unordered_map<uint64_t, Flow> flows_;
    std::unordered_map<uint64_t, StreamingFlow> streamingFlows_;
    std::unordered_map<uint64_t, double> flowLastActivity_;
    size_t processedPackets_ = 0;
    static constexpr size_t CLEANUP_INTERVAL = 10000; // Clean up every 10k packets
    
    // Helper functions
    uint64_t getFlowId(const std::string& srcIp, const std::string& dstIp,
                       uint16_t srcPort, uint16_t dstPort, uint8_t protocol);
    
    bool isForwardDirection(const std::string& srcIp, const std::string& dstIp,
                           uint16_t srcPort, uint16_t dstPort,
                           const std::string& flowSrcIp, uint16_t flowSrcPort);
    
    PacketInfo extractPacketInfo(pcpp::Packet& packet);
    
    // Statistical calculations
    Statistics calculateStatistics(const std::vector<double>& values);
    Statistics calculateIAT(const std::vector<PacketInfo>& packets);
    
    // Enhanced feature calculations
    std::pair<double, int> calculateBulkFeatures(const std::vector<PacketInfo>& packets);
    std::pair<std::vector<double>, std::vector<double>> calculateActiveIdleTimes(const std::vector<PacketInfo>& packets);
    int detectRetransmissions(const std::vector<PacketInfo>& packets);
    
    // Memory management functions
    void cleanupExpiredFlows(double currentTime);
    void periodicCleanup(double currentTime);
    size_t getMemoryUsage() const;
    
    // Helper functions for optimized packet access
    std::vector<PacketInfo> getForwardPackets(const Flow& flow) const;
    std::vector<PacketInfo> getBackwardPackets(const Flow& flow) const;
    
    // IP hashing helper
    uint32_t hashIpAddress(const std::string& ip) const;
    
    // Helper functions for streaming processing
    void processPacketStreaming(pcpp::Packet& packet);
    void updateStreamingFlow(StreamingFlow& flow, const PacketInfo& packet, bool isForward);
    FlowFeatures extractStreamingFlowFeatures(uint64_t flowId, const StreamingFlow& flow);
    
    // Helper functions for new feature calculations
    double calculatePayloadEntropy(const std::vector<PacketInfo>& packets);
    double calculateHeaderEntropy(const std::vector<PacketInfo>& packets);
    std::string detectApplicationProtocol(const Flow& flow);
    std::pair<int, int> extractTLSFeatures(const std::vector<PacketInfo>& packets);
    double calculateBurstiness(const std::vector<PacketInfo>& packets);
    double calculateJitter(const std::vector<PacketInfo>& packets);
    int calculateDirectionChanges(const Flow& flow);
    double calculateFlowPersistence(const std::vector<PacketInfo>& packets, double duration);
    bool isInternalTraffic(const std::string& srcIp, const std::string& dstIp);
    std::string categorizePort(uint16_t srcPort, uint16_t dstPort);
    double calculateSkewness(const std::vector<double>& values);
    double calculateKurtosis(const std::vector<double>& values);
    
    // Feature selection helpers
    std::set<std::string> resolveSelectedFeatures() const;
    std::vector<std::string> getCSVHeader(const std::set<std::string>& selectedFeatures) const;
    std::string getFeatureValue(const FlowFeatures& feature, const std::string& featureName) const;
    
    // Number formatting helper
    std::string formatNumber(double value) const;
    std::string formatNumber(int value) const;
    std::string formatNumber(uint32_t value) const;
    std::string formatNumber(uint64_t value) const;
};

// Configuration helper functions
Config getDefaultConfig();
Config getHighPerformanceConfig();
Config getDetailedAnalysisConfig();
Config getRealTimeConfig();
Config getConfig(const std::string& configName);
bool validateConfig(const Config& config);
void printConfig(const Config& config);

#endif // FLOW_ANALYZER_H