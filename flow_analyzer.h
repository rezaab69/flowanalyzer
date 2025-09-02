#ifndef FLOW_ANALYZER_H
#define FLOW_ANALYZER_H

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <cstdint>
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
};

// Packet information structure
struct PacketInfo {
    double timestamp = 0.0;
    uint32_t length = 0;
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t protocol = 0;
    uint32_t headerLength = 0;
    uint32_t payloadLength = 0;
    std::map<std::string, bool> flags;
    uint8_t icmpCode = 0;
    uint8_t icmpType = 0;
    uint16_t windowSize = 0;
};

// Flow structure
struct Flow {
    std::vector<PacketInfo> packets;
    std::vector<PacketInfo> fwdPackets;
    std::vector<PacketInfo> bwdPackets;
    double startTime = 0.0;
    double endTime = 0.0;
    uint8_t protocol = 0;
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    
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
    
    // TCP Flags
    int fwdPSHFlags;
    int bwdPSHFlags;
    int fwdURGFlags;
    int bwdURGFlags;
    int fwdRSTFlags;
    int bwdRSTFlags;
    
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
    
    // Total connection flow time
    double totalConnectionFlowTime;
};

// Main flow feature extractor class
class FlowFeatureExtractor {
public:
    explicit FlowFeatureExtractor(const Config& config = Config());
    
    // Main analysis functions
    std::vector<FlowFeatures> analyzePcap(const std::string& pcapFile);
    void exportToCSV(const std::vector<FlowFeatures>& features, const std::string& outputFile);
    
    // Packet processing
    void processPacket(pcpp::Packet& packet);
    
    // Feature extraction
    FlowFeatures extractFlowFeatures(const std::string& flowId, const Flow& flow);
    
private:
    Config config_;
    std::unordered_map<std::string, Flow> flows_;
    
    // Helper functions
    std::string getFlowId(const std::string& srcIp, const std::string& dstIp,
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