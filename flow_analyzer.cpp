#include "flow_analyzer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <chrono>
#include <numeric>
#include <cstring>

// Feature group definitions
const std::set<std::string> FeatureGroups::BASIC = {
    "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
    "Flow Duration", "Total Fwd Packet", "Total Bwd packets"
};

const std::set<std::string> FeatureGroups::TIMING = {
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
};

const std::set<std::string> FeatureGroups::FLAGS = {
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd RST Flags", "Bwd RST Flags",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count"
};

const std::set<std::string> FeatureGroups::BULK = {
    "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg"
};

const std::set<std::string> FeatureGroups::WINDOW = {
    "FWD Init Win Bytes", "Bwd Init Win Bytes"
};

const std::set<std::string> FeatureGroups::RETRANSMISSION = {
    "Fwd TCP Retrans. Count", "Bwd TCP Retrans. Count", "Total TCP Retrans. Count"
};

const std::set<std::string> FeatureGroups::ICMP = {
    "ICMP Code", "ICMP Type"
};

const std::set<std::string> FeatureGroups::STATISTICS = {
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
    "Fwd Header Length", "Bwd Header Length",
    "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "Down/Up Ratio", "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Fwd Act Data Pkts", "Bwd Act Data Pkts", "Fwd Seg Size Min", "Bwd Seg Size Min",
    "Total Connection Flow Time"
};

const std::set<std::string> FeatureGroups::RATIOS = {
    "Fwd Bwd Packet Ratio", "Fwd Bwd Byte Ratio", "Average Packet Rate"
};

const std::set<std::string> FeatureGroups::ENTROPY = {
    "Payload Entropy", "Header Entropy"
};

const std::set<std::string> FeatureGroups::PROTOCOL = {
    "Application Protocol", "TLS Cert Count", "TLS Session ID Length"
};

const std::set<std::string> FeatureGroups::BEHAVIORAL = {
    "Burstiness", "Packet IAT Jitter", "Direction Change Count", "Average Idle Time", "Flow Persistence"
};

const std::set<std::string> FeatureGroups::NETWORK = {
    "Internal External Flag", "Port Category"
};

const std::set<std::string> FeatureGroups::HIGHER_ORDER = {
    "Packet Length Skewness", "Packet Length Kurtosis", "IAT Skewness", "IAT Kurtosis"
};

const std::set<std::string> FeatureGroups::ALL = {
    // Combine all feature groups
};

FlowFeatureExtractor::FlowFeatureExtractor(const Config& config) : config_(config) {
    // Initialize with provided configuration
}

uint64_t FlowFeatureExtractor::getFlowId(const std::string& srcIp, const std::string& dstIp,
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
    
    // Use std::hash to generate a 64-bit hash directly
    std::hash<std::string> hasher;
    return static_cast<uint64_t>(hasher(flowTuple));
}

bool FlowFeatureExtractor::isForwardDirection(const std::string& srcIp, const std::string& /* dstIp */,
                                            uint16_t srcPort, uint16_t /* dstPort */,
                                            const std::string& flowSrcIp, uint16_t flowSrcPort) {
    return srcIp == flowSrcIp && srcPort == flowSrcPort;
}

PacketInfo FlowFeatureExtractor::extractPacketInfo(pcpp::Packet& packet) {
    PacketInfo info;
    info.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() / 1000000.0;
    
    uint32_t packetLen = packet.getRawPacket()->getRawDataLen();
    info.length = (packetLen > 65535) ? 65535 : static_cast<uint16_t>(packetLen);
    info.headerLength = 0;
    info.payloadLength = 0;
    
    // Initialize TCP flags
    memset(&info.tcpFlags, 0, sizeof(info.tcpFlags));
    
    // Extract IP layer information
    pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ipv4Layer) {
        info.srcIp = ipv4Layer->getSrcIPAddress().toString();
        info.dstIp = ipv4Layer->getDstIPAddress().toString();
        info.srcIpHash = hashIpAddress(info.srcIp);
        info.dstIpHash = hashIpAddress(info.dstIp);
        info.protocol = ipv4Layer->getIPv4Header()->protocol;
        uint32_t headerLen = ipv4Layer->getHeaderLen();
        info.headerLength += (headerLen > 65535) ? 65535 : static_cast<uint16_t>(headerLen);
    }
    
    // Extract TCP layer information
    pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (tcpLayer) {
        info.srcPort = tcpLayer->getSrcPort();
        info.dstPort = tcpLayer->getDstPort();
        info.protocol = 6; // TCP
        uint32_t tcpHeaderLen = tcpLayer->getHeaderLen();
        info.headerLength += (tcpHeaderLen > 65535) ? 65535 : static_cast<uint16_t>(tcpHeaderLen);
        info.windowSize = tcpLayer->getTcpHeader()->windowSize;
        
        // Extract TCP flags to bit fields
        pcpp::tcphdr* tcpHeader = tcpLayer->getTcpHeader();
        info.tcpFlags.fin = tcpHeader->finFlag;
        info.tcpFlags.syn = tcpHeader->synFlag;
        info.tcpFlags.rst = tcpHeader->rstFlag;
        info.tcpFlags.psh = tcpHeader->pshFlag;
        info.tcpFlags.ack = tcpHeader->ackFlag;
        info.tcpFlags.urg = tcpHeader->urgFlag;
        info.tcpFlags.cwr = tcpHeader->cwrFlag;
        info.tcpFlags.ece = tcpHeader->eceFlag;
        
        // Keep compatibility flags
        info.flags["FIN"] = tcpHeader->finFlag;
        info.flags["SYN"] = tcpHeader->synFlag;
        info.flags["RST"] = tcpHeader->rstFlag;
        info.flags["PSH"] = tcpHeader->pshFlag;
        info.flags["ACK"] = tcpHeader->ackFlag;
        info.flags["URG"] = tcpHeader->urgFlag;
        info.flags["CWR"] = tcpHeader->cwrFlag;
        info.flags["ECE"] = tcpHeader->eceFlag;
    }
    
    // Extract UDP layer information
    pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (udpLayer) {
        info.srcPort = udpLayer->getSrcPort();
        info.dstPort = udpLayer->getDstPort();
        info.protocol = 17; // UDP
        info.headerLength += 8; // UDP header length
    }
    
    // Extract ICMP layer information
    pcpp::IcmpLayer* icmpLayer = packet.getLayerOfType<pcpp::IcmpLayer>();
    if (icmpLayer) {
        info.protocol = 1; // ICMP
        info.srcPort = 0;
        info.dstPort = 0;
        info.icmpCode = icmpLayer->getIcmpHeader()->code;
        info.icmpType = icmpLayer->getIcmpHeader()->type;
    }
    
    uint32_t payloadLen = info.length - info.headerLength;
    info.payloadLength = (payloadLen > 65535) ? 65535 : static_cast<uint16_t>(payloadLen);
    return info;
}

void FlowFeatureExtractor::processPacket(pcpp::Packet& packet) {
    try {
        // Use streaming processing if enabled
        if (config_.enableStreaming) {
            processPacketStreaming(packet);
            processedPackets_++;
            
            // Periodic cleanup for streaming flows
             if (processedPackets_ % 10000 == 0) {
                PacketInfo pktInfo = extractPacketInfo(packet);
                periodicCleanup(pktInfo.timestamp);
            }
            return;
        }
        
        // Traditional processing with full packet storage
        PacketInfo pktInfo = extractPacketInfo(packet);
        
        if (pktInfo.srcIp.empty() || pktInfo.dstIp.empty()) {
            return;
        }
        
        uint64_t flowId = getFlowId(pktInfo.srcIp, pktInfo.dstIp,
                                    pktInfo.srcPort, pktInfo.dstPort, pktInfo.protocol);
        
        // Update flow activity tracking
        flowLastActivity_[flowId] = pktInfo.timestamp;
        
        // Periodic cleanup to manage memory
        processedPackets_++;
        if (processedPackets_ % CLEANUP_INTERVAL == 0) {
            periodicCleanup(pktInfo.timestamp);
        }
        
        Flow& flow = flows_[flowId];
        
        // Limit packets per flow to prevent memory issues
        if (static_cast<int>(flow.packets.size()) >= config_.maxFlowPackets) {
            return;
        }
        
        // Initialize flow if first packet
        if (flow.packets.empty()) {
            flow.srcIp = pktInfo.srcIp;
            flow.dstIp = pktInfo.dstIp;
            flow.srcPort = pktInfo.srcPort;
            flow.dstPort = pktInfo.dstPort;
            flow.protocol = pktInfo.protocol;
            flow.startTime = pktInfo.timestamp;
            flow.icmpCode = pktInfo.icmpCode;
            flow.icmpType = pktInfo.icmpType;
            
            if (pktInfo.windowSize > 0) {
                flow.fwdInitWin = pktInfo.windowSize;
            }
        }
        
        flow.endTime = pktInfo.timestamp;
        flow.packets.push_back(pktInfo);
        
        // Determine packet direction
        bool isForward = isForwardDirection(pktInfo.srcIp, pktInfo.dstIp,
                                          pktInfo.srcPort, pktInfo.dstPort,
                                          flow.srcIp, flow.srcPort);
        
        // Store direction flag and update counters
        flow.isForward.push_back(isForward);
        
        if (isForward) {
            flow.fwdPacketCount++;
            // Update forward flags
            for (const auto& flag : pktInfo.flags) {
                if (flow.fwdFlags.find(flag.first) != flow.fwdFlags.end() && flag.second) {
                    flow.fwdFlags[flag.first]++;
                }
            }
        } else {
            flow.bwdPacketCount++;
            // Update backward flags
            for (const auto& flag : pktInfo.flags) {
                if (flow.bwdFlags.find(flag.first) != flow.bwdFlags.end() && flag.second) {
                    flow.bwdFlags[flag.first]++;
                }
            }
            
            // Set backward initial window size
            if (pktInfo.windowSize > 0 && flow.bwdInitWin == 0) {
                flow.bwdInitWin = pktInfo.windowSize;
            }
        }
        
        // Update overall flags
        for (const auto& flag : pktInfo.flags) {
            if (flag.second) {
                flow.flags[flag.first]++;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error processing packet: " << e.what() << std::endl;
    }
}

Statistics FlowFeatureExtractor::calculateStatistics(const std::vector<double>& values) {
    Statistics stats = {0, 0, 0, 0, 0};
    
    if (values.empty()) {
        return stats;
    }
    
    stats.total = std::accumulate(values.begin(), values.end(), 0.0);
    stats.mean = stats.total / values.size();
    stats.min = *std::min_element(values.begin(), values.end());
    stats.max = *std::max_element(values.begin(), values.end());
    
    if (values.size() > 1) {
        double variance = 0.0;
        for (double value : values) {
            variance += (value - stats.mean) * (value - stats.mean);
        }
        stats.std = std::sqrt(variance / (values.size() - 1));
    }
    
    return stats;
}

Statistics FlowFeatureExtractor::calculateIAT(const std::vector<PacketInfo>& packets) {
    Statistics stats = {0, 0, 0, 0, 0};
    
    if (packets.size() < 2) {
        return stats;
    }
    
    std::vector<double> iats;
    for (size_t i = 1; i < packets.size(); i++) {
        double iat = (packets[i].timestamp - packets[i-1].timestamp) * 1000000; // microseconds
        iats.push_back(iat);
    }
    
    return calculateStatistics(iats);
}

std::pair<double, int> FlowFeatureExtractor::calculateBulkFeatures(const std::vector<PacketInfo>& packets) {
    if (!config_.enableBulkDetection || static_cast<int>(packets.size()) < config_.bulkThreshold) {
        return {0, 0};
    }
    
    double bulkBytes = 0;
    int bulkPackets = 0;
    int consecutiveCount = 0;
    
    try {
        for (const auto& packet : packets) {
            if (packet.payloadLength > 0) {
                consecutiveCount++;
                if (consecutiveCount >= config_.bulkThreshold) {
                    bulkBytes += packet.length;
                    bulkPackets++;
                }
            } else {
                consecutiveCount = 0;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Warning: Error in bulk feature calculation: " << e.what() << std::endl;
        return {0, 0};
    }
    
    return {bulkBytes, bulkPackets};
}

std::pair<std::vector<double>, std::vector<double>> 
FlowFeatureExtractor::calculateActiveIdleTimes(const std::vector<PacketInfo>& packets) {
    std::vector<double> activeTimes, idleTimes;
    
    if (!config_.enableActiveIdle || packets.size() < 2) {
        return {activeTimes, idleTimes};
    }
    
    try {
        for (size_t i = 1; i < packets.size(); i++) {
            double timeDiff = packets[i].timestamp - packets[i-1].timestamp;
            
            if (timeDiff <= config_.activeThreshold) {
                activeTimes.push_back(timeDiff * 1000000); // microseconds
            } else {
                idleTimes.push_back(timeDiff * 1000000); // microseconds
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Warning: Error in active/idle time calculation: " << e.what() << std::endl;
    }
    
    return {activeTimes, idleTimes};
}

int FlowFeatureExtractor::detectRetransmissions(const std::vector<PacketInfo>& packets) {
    if (!config_.enableRetransDetection || packets.empty()) {
        return 0;
    }
    
    int retransCount = 0;
    std::set<std::string> seenSequences;
    
    try {
        for (const auto& packet : packets) {
            if (packet.protocol == 6) { // TCP protocol
                std::string seqId = packet.srcIp + ":" + std::to_string(packet.srcPort) + "-" +
                                   packet.dstIp + ":" + std::to_string(packet.dstPort) + "-" +
                                   std::to_string(packet.length);
                
                if (seenSequences.find(seqId) != seenSequences.end()) {
                    retransCount++;
                } else {
                    seenSequences.insert(seqId);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Warning: Error in retransmission detection: " << e.what() << std::endl;
        return 0;
    }
    
    return retransCount;
}

FlowFeatures FlowFeatureExtractor::extractFlowFeatures(const uint64_t& flowId, const Flow& flow) {
    FlowFeatures features;
    
    // Basic flow information
    features.flowId = std::to_string(flowId);
    features.srcIp = flow.srcIp;
    features.srcPort = flow.srcPort;
    features.dstIp = flow.dstIp;
    features.dstPort = flow.dstPort;
    features.protocol = flow.protocol;
    
    // Convert timestamp to readable format
    auto timePoint = std::chrono::system_clock::from_time_t(static_cast<time_t>(flow.startTime));
    auto timeT = std::chrono::system_clock::to_time_t(timePoint);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&timeT), "%Y-%m-%d %H:%M:%S");
    features.timestamp = ss.str();
    
    // Flow duration
    double duration = (flow.endTime - flow.startTime);
    features.flowDuration = duration * 1000000; // microseconds
    
    // Get forward and backward packets using helper functions
    std::vector<PacketInfo> fwdPackets = getForwardPackets(flow);
    std::vector<PacketInfo> bwdPackets = getBackwardPackets(flow);
    
    // Packet counts
    features.totalFwdPackets = fwdPackets.size();
    features.totalBwdPackets = bwdPackets.size();
    
    // Calculate packet length statistics
    std::vector<double> fwdLengths, bwdLengths, allLengths;
    for (const auto& p : fwdPackets) fwdLengths.push_back(p.length);
    for (const auto& p : bwdPackets) bwdLengths.push_back(p.length);
    for (const auto& p : flow.packets) allLengths.push_back(p.length);
    
    Statistics fwdStats = calculateStatistics(fwdLengths);
    Statistics bwdStats = calculateStatistics(bwdLengths);
    Statistics allStats = calculateStatistics(allLengths);
    
    features.totalLengthFwdPackets = fwdStats.total;
    features.totalLengthBwdPackets = bwdStats.total;
    features.fwdPacketLengthMax = fwdStats.max;
    features.fwdPacketLengthMin = fwdStats.min;
    features.fwdPacketLengthMean = fwdStats.mean;
    features.fwdPacketLengthStd = fwdStats.std;
    features.bwdPacketLengthMax = bwdStats.max;
    features.bwdPacketLengthMin = bwdStats.min;
    features.bwdPacketLengthMean = bwdStats.mean;
    features.bwdPacketLengthStd = bwdStats.std;
    
    // Flow rates
    if (duration > 0) {
        features.flowBytesPerSec = (fwdStats.total + bwdStats.total) / duration;
        features.flowPacketsPerSec = flow.packets.size() / duration;
        features.fwdPacketsPerSec = fwdPackets.size() / duration;
        features.bwdPacketsPerSec = bwdPackets.size() / duration;
    } else {
        features.flowBytesPerSec = 0;
        features.flowPacketsPerSec = 0;
        features.fwdPacketsPerSec = 0;
        features.bwdPacketsPerSec = 0;
    }
    
    // Inter-arrival times
    Statistics flowIAT = calculateIAT(flow.packets);
    Statistics fwdIAT = calculateIAT(fwdPackets);
    Statistics bwdIAT = calculateIAT(bwdPackets);
    
    features.flowIATMean = flowIAT.mean;
    features.flowIATStd = flowIAT.std;
    features.flowIATMax = flowIAT.max;
    features.flowIATMin = flowIAT.min;
    features.fwdIATTotal = fwdIAT.total;
    features.fwdIATMean = fwdIAT.mean;
    features.fwdIATStd = fwdIAT.std;
    features.fwdIATMax = fwdIAT.max;
    features.fwdIATMin = fwdIAT.min;
    features.bwdIATTotal = bwdIAT.total;
    features.bwdIATMean = bwdIAT.mean;
    features.bwdIATStd = bwdIAT.std;
    features.bwdIATMax = bwdIAT.max;
    features.bwdIATMin = bwdIAT.min;
    
    // TCP Flags
    features.fwdPSHFlags = flow.fwdFlags.at("PSH");
    features.bwdPSHFlags = flow.bwdFlags.at("PSH");
    features.fwdURGFlags = flow.fwdFlags.at("URG");
    features.bwdURGFlags = flow.bwdFlags.at("URG");
    features.fwdRSTFlags = flow.fwdFlags.at("RST");
    features.bwdRSTFlags = flow.bwdFlags.at("RST");
    
    // Header lengths
    double fwdHeaderLength = 0, bwdHeaderLength = 0;
    for (const auto& p : fwdPackets) fwdHeaderLength += p.headerLength;
    for (const auto& p : bwdPackets) bwdHeaderLength += p.headerLength;
    features.fwdHeaderLength = fwdHeaderLength;
    features.bwdHeaderLength = bwdHeaderLength;
    
    // Packet statistics
    features.packetLengthMin = allStats.min;
    features.packetLengthMax = allStats.max;
    features.packetLengthMean = allStats.mean;
    features.packetLengthStd = allStats.std;
    features.packetLengthVariance = allStats.std * allStats.std;
    
    // Flag counts
    features.finFlagCount = flow.flags.at("FIN");
    features.synFlagCount = flow.flags.at("SYN");
    features.rstFlagCount = flow.flags.at("RST");
    features.pshFlagCount = flow.flags.at("PSH");
    features.ackFlagCount = flow.flags.at("ACK");
    features.urgFlagCount = flow.flags.at("URG");
    features.cwrFlagCount = flow.flags.at("CWR");
    features.eceFlagCount = flow.flags.at("ECE");
    
    // Ratios and averages
    features.downUpRatio = features.totalFwdPackets > 0 ? 
        static_cast<double>(features.totalBwdPackets) / features.totalFwdPackets : 0;
    features.averagePacketSize = allStats.mean;
    
    // Segment sizes (payload)
    std::vector<double> fwdPayloads, bwdPayloads;
    for (const auto& p : fwdPackets) {
        if (p.payloadLength > 0) fwdPayloads.push_back(p.payloadLength);
    }
    for (const auto& p : bwdPackets) {
        if (p.payloadLength > 0) bwdPayloads.push_back(p.payloadLength);
    }
    
    features.fwdSegmentSizeAvg = fwdPayloads.empty() ? 0 : 
        std::accumulate(fwdPayloads.begin(), fwdPayloads.end(), 0.0) / fwdPayloads.size();
    features.bwdSegmentSizeAvg = bwdPayloads.empty() ? 0 : 
        std::accumulate(bwdPayloads.begin(), bwdPayloads.end(), 0.0) / bwdPayloads.size();
    
    // Bulk transfer features
    auto fwdBulk = calculateBulkFeatures(fwdPackets);
    auto bwdBulk = calculateBulkFeatures(bwdPackets);
    
    features.fwdBytesBulkAvg = fwdBulk.first / std::max(1, static_cast<int>(fwdPackets.size()));
    features.fwdPacketBulkAvg = fwdBulk.second / std::max(1, static_cast<int>(fwdPackets.size()));
    features.fwdBulkRateAvg = duration > 0 ? fwdBulk.first / duration : 0;
    features.bwdBytesBulkAvg = bwdBulk.first / std::max(1, static_cast<int>(bwdPackets.size()));
    features.bwdPacketBulkAvg = bwdBulk.second / std::max(1, static_cast<int>(bwdPackets.size()));
    features.bwdBulkRateAvg = duration > 0 ? bwdBulk.first / duration : 0;
    
    // Subflow features (same as flow for basic implementation)
    features.subflowFwdPackets = features.totalFwdPackets;
    features.subflowFwdBytes = features.totalLengthFwdPackets;
    features.subflowBwdPackets = features.totalBwdPackets;
    features.subflowBwdBytes = features.totalLengthBwdPackets;
    
    // Window sizes
    features.fwdInitWinBytes = flow.fwdInitWin;
    features.bwdInitWinBytes = flow.bwdInitWin;
    
    // Active data packets
    features.fwdActDataPkts = fwdPayloads.size();
    features.bwdActDataPkts = bwdPayloads.size();
    
    // Minimum segment sizes
    features.fwdSegSizeMin = fwdPayloads.empty() ? 0 : *std::min_element(fwdPayloads.begin(), fwdPayloads.end());
    features.bwdSegSizeMin = bwdPayloads.empty() ? 0 : *std::min_element(bwdPayloads.begin(), bwdPayloads.end());
    
    // Active/Idle times
    auto activeIdle = calculateActiveIdleTimes(flow.packets);
    Statistics activeStats = calculateStatistics(activeIdle.first);
    Statistics idleStats = calculateStatistics(activeIdle.second);
    
    features.activeMean = activeStats.mean;
    features.activeStd = activeStats.std;
    features.activeMax = activeStats.max;
    features.activeMin = activeStats.min;
    features.idleMean = idleStats.mean;
    features.idleStd = idleStats.std;
    features.idleMax = idleStats.max;
    features.idleMin = idleStats.min;
    
    // ICMP features
    features.icmpCode = flow.icmpCode;
    features.icmpType = flow.icmpType;
    
    // Retransmission counts
    int fwdRetrans = detectRetransmissions(fwdPackets);
    int bwdRetrans = detectRetransmissions(bwdPackets);
    
    features.fwdTCPRetransCount = fwdRetrans;
    features.bwdTCPRetransCount = bwdRetrans;
    features.totalTCPRetransCount = fwdRetrans + bwdRetrans;
    
    // Total connection flow time
    features.totalConnectionFlowTime = features.flowDuration;
    
    // Forward/Backward ratio features
    features.fwdBwdPacketRatio = features.totalBwdPackets > 0 ? 
        static_cast<double>(features.totalFwdPackets) / features.totalBwdPackets : 0;
    features.fwdBwdByteRatio = features.totalLengthBwdPackets > 0 ? 
        features.totalLengthFwdPackets / features.totalLengthBwdPackets : 0;
    features.averagePacketRate = duration > 0 ? flow.packets.size() / duration : 0;
    
    // Entropy-based features
    features.payloadEntropy = calculatePayloadEntropy(flow.packets);
    features.headerEntropy = calculateHeaderEntropy(flow.packets);
    
    // Application/Protocol context features
    features.applicationProtocol = detectApplicationProtocol(flow);
    auto tlsFeatures = extractTLSFeatures(flow.packets);
    features.tlsCertificateCount = tlsFeatures.first;
    features.tlsSessionIdLength = tlsFeatures.second;
    features.tlsCipherSuite = "Unknown"; // Placeholder for cipher suite detection
    
    // Time-based features
    features.burstiness = calculateBurstiness(flow.packets);
    features.packetInterArrivalJitter = calculateJitter(flow.packets);
    
    // Behavioral features
    features.directionChangeCount = calculateDirectionChanges(flow);
    features.averageIdleTime = idleStats.mean;
    features.flowPersistence = calculateFlowPersistence(flow.packets, duration);
    
    // Network context features
    features.isInternalExternal = isInternalTraffic(flow.srcIp, flow.dstIp);
    features.portCategory = categorizePort(flow.srcPort, flow.dstPort);
    
    // Higher-order statistics
    features.packetLengthSkewness = calculateSkewness(allLengths);
    features.packetLengthKurtosis = calculateKurtosis(allLengths);
    
    std::vector<double> iatValues;
    for (size_t i = 1; i < flow.packets.size(); ++i) {
        iatValues.push_back(flow.packets[i].timestamp - flow.packets[i-1].timestamp);
    }
    features.iatSkewness = calculateSkewness(iatValues);
    features.iatKurtosis = calculateKurtosis(iatValues);
    
    return features;
}

std::vector<FlowFeatures> FlowFeatureExtractor::analyzePcap(const std::string& pcapFile) {
    std::cout << "Analyzing PCAP file: " << pcapFile << std::endl;
    
    std::vector<FlowFeatures> flowFeatures;
    
    try {
        pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFile);
        
        if (reader == nullptr) {
            std::cerr << "Cannot determine reader for file type" << std::endl;
            return flowFeatures;
        }
        
        if (!reader->open()) {
            std::cerr << "Cannot open pcap file" << std::endl;
            delete reader;
            return flowFeatures;
        }
        
        pcpp::RawPacket rawPacket;
        int packetCount = 0;
        
        while (reader->getNextPacket(rawPacket)) {
            pcpp::Packet packet(&rawPacket);
            processPacket(packet);
            packetCount++;
            
            if (packetCount % 1000 == 0) {
                std::cout << "Processed " << packetCount << " packets..." << std::endl;
            }
        }
        
        reader->close();
        delete reader;
        
        std::cout << "Total packets processed: " << packetCount << std::endl;
        std::cout << "Total flows identified: " << flows_.size() << std::endl;
        
        // Extract features for all flows
        for (const auto& flowPair : flows_) {
            FlowFeatures features = extractFlowFeatures(flowPair.first, flowPair.second);
            flowFeatures.push_back(features);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error reading PCAP file: " << e.what() << std::endl;
    }
    
    return flowFeatures;
}

void FlowFeatureExtractor::exportToCSV(const std::vector<FlowFeatures>& features, const std::string& outputFile) {
    if (features.empty()) {
        std::cout << "No features to export" << std::endl;
        return;
    }
    
    // Check if selective output is enabled
    if (config_.useSelectiveOutput) {
        std::set<std::string> selectedFeatures = resolveSelectedFeatures();
        exportSelectiveCSV(features, outputFile, selectedFeatures);
        return;
    }
    
    // Original full export functionality
    std::ofstream file(outputFile);
    if (!file.is_open()) {
        std::cerr << "Cannot open output file: " << outputFile << std::endl;
        return;
    }
    
    // Write CSV header
    file << "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,"
         << "Flow Duration,Total Fwd Packet,Total Bwd packets,"
         << "Total Length of Fwd Packet,Total Length of Bwd Packet,"
         << "Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
         << "Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,"
         << "Flow Bytes/s,Flow Packets/s,Fwd Packets/s,Bwd Packets/s,"
         << "Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,"
         << "Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,"
         << "Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,"
         << "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd RST Flags,Bwd RST Flags,"
         << "Fwd Header Length,Bwd Header Length,"
         << "Packet Length Min,Packet Length Max,Packet Length Mean,Packet Length Std,Packet Length Variance,"
         << "FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWR Flag Count,ECE Flag Count,"
         << "Down/Up Ratio,Average Packet Size,Fwd Segment Size Avg,Bwd Segment Size Avg,"
         << "Fwd Bytes/Bulk Avg,Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,Bwd Bytes/Bulk Avg,Bwd Packet/Bulk Avg,Bwd Bulk Rate Avg,"
         << "Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,"
         << "FWD Init Win Bytes,Bwd Init Win Bytes,Fwd Act Data Pkts,Bwd Act Data Pkts,Fwd Seg Size Min,Bwd Seg Size Min,"
         << "Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,"
         << "ICMP Code,ICMP Type,Fwd TCP Retrans. Count,Bwd TCP Retrans. Count,Total TCP Retrans. Count,Total Connection Flow Time,"
         << "Fwd Bwd Packet Ratio,Fwd Bwd Byte Ratio,Average Packet Rate,"
         << "Payload Entropy,Header Entropy,"
         << "Application Protocol,TLS Cert Count,TLS Session ID Length,TLS Cipher Suite,"
         << "Burstiness,Packet IAT Jitter,"
         << "Direction Change Count,Average Idle Time,Flow Persistence,"
         << "Internal External Flag,Port Category,"
         << "Packet Length Skewness,Packet Length Kurtosis,IAT Skewness,IAT Kurtosis\n";
    
    // Write data rows
    for (const auto& feature : features) {
        file << feature.flowId << "," << feature.srcIp << "," << feature.srcPort << ","
             << feature.dstIp << "," << feature.dstPort << "," << static_cast<int>(feature.protocol) << ","
             << feature.timestamp << "," << feature.flowDuration << ","
             << feature.totalFwdPackets << "," << feature.totalBwdPackets << ","
             << feature.totalLengthFwdPackets << "," << feature.totalLengthBwdPackets << ","
             << feature.fwdPacketLengthMax << "," << feature.fwdPacketLengthMin << ","
             << feature.fwdPacketLengthMean << "," << feature.fwdPacketLengthStd << ","
             << feature.bwdPacketLengthMax << "," << feature.bwdPacketLengthMin << ","
             << feature.bwdPacketLengthMean << "," << feature.bwdPacketLengthStd << ","
             << feature.flowBytesPerSec << "," << feature.flowPacketsPerSec << ","
             << feature.fwdPacketsPerSec << "," << feature.bwdPacketsPerSec << ","
             << feature.flowIATMean << "," << feature.flowIATStd << ","
             << feature.flowIATMax << "," << feature.flowIATMin << ","
             << feature.fwdIATTotal << "," << feature.fwdIATMean << ","
             << feature.fwdIATStd << "," << feature.fwdIATMax << "," << feature.fwdIATMin << ","
             << feature.bwdIATTotal << "," << feature.bwdIATMean << ","
             << feature.bwdIATStd << "," << feature.bwdIATMax << "," << feature.bwdIATMin << ","
             << feature.fwdPSHFlags << "," << feature.bwdPSHFlags << ","
             << feature.fwdURGFlags << "," << feature.bwdURGFlags << ","
             << feature.fwdRSTFlags << "," << feature.bwdRSTFlags << ","
             << feature.fwdHeaderLength << "," << feature.bwdHeaderLength << ","
             << feature.packetLengthMin << "," << feature.packetLengthMax << ","
             << feature.packetLengthMean << "," << feature.packetLengthStd << ","
             << feature.packetLengthVariance << ","
             << feature.finFlagCount << "," << feature.synFlagCount << ","
             << feature.rstFlagCount << "," << feature.pshFlagCount << ","
             << feature.ackFlagCount << "," << feature.urgFlagCount << ","
             << feature.cwrFlagCount << "," << feature.eceFlagCount << ","
             << feature.downUpRatio << "," << feature.averagePacketSize << ","
             << feature.fwdSegmentSizeAvg << "," << feature.bwdSegmentSizeAvg << ","
             << feature.fwdBytesBulkAvg << "," << feature.fwdPacketBulkAvg << ","
             << feature.fwdBulkRateAvg << "," << feature.bwdBytesBulkAvg << ","
             << feature.bwdPacketBulkAvg << "," << feature.bwdBulkRateAvg << ","
             << feature.subflowFwdPackets << "," << feature.subflowFwdBytes << ","
             << feature.subflowBwdPackets << "," << feature.subflowBwdBytes << ","
             << feature.fwdInitWinBytes << "," << feature.bwdInitWinBytes << ","
             << feature.fwdActDataPkts << "," << feature.bwdActDataPkts << ","
             << feature.fwdSegSizeMin << "," << feature.bwdSegSizeMin << ","
             << feature.activeMean << "," << feature.activeStd << ","
             << feature.activeMax << "," << feature.activeMin << ","
             << feature.idleMean << "," << feature.idleStd << ","
             << feature.idleMax << "," << feature.idleMin << ","
             << static_cast<int>(feature.icmpCode) << "," << static_cast<int>(feature.icmpType) << ","
             << feature.fwdTCPRetransCount << "," << feature.bwdTCPRetransCount << ","
             << feature.totalTCPRetransCount << "," << feature.totalConnectionFlowTime << ","
             << feature.fwdBwdPacketRatio << "," << feature.fwdBwdByteRatio << "," << feature.averagePacketRate << ","
             << feature.payloadEntropy << "," << feature.headerEntropy << ","
             << feature.applicationProtocol << "," << feature.tlsCertificateCount << "," << feature.tlsSessionIdLength << ","
             << feature.tlsCipherSuite << ","
             << feature.burstiness << "," << feature.packetInterArrivalJitter << ","
             << feature.directionChangeCount << "," << feature.averageIdleTime << "," << feature.flowPersistence << ","
             << (feature.isInternalExternal ? "Internal" : "External") << "," << feature.portCategory << ","
             << feature.packetLengthSkewness << "," << feature.packetLengthKurtosis << "," << feature.iatSkewness << "," << feature.iatKurtosis << "\n";
    }
    
    file.close();
    std::cout << "Flow features exported to: " << outputFile << std::endl;
    std::cout << "Total flows exported: " << features.size() << std::endl;
}

// Memory management functions
void FlowFeatureExtractor::cleanupExpiredFlows(double currentTime) {
    if (config_.enableStreaming) {
        // Cleanup streaming flows
        auto streamingFlowIt = streamingFlows_.begin();
        while (streamingFlowIt != streamingFlows_.end()) {
            const uint64_t& flowId = streamingFlowIt->first;
            auto activityEntry = flowLastActivity_.find(flowId);
            
            if (activityEntry != flowLastActivity_.end()) {
                double timeSinceLastActivity = currentTime - activityEntry->second;
                
                if (timeSinceLastActivity > config_.flowTimeout) {
                    if (config_.verbose) {
                        std::cout << "Cleaning up expired streaming flow: " << flowId << std::endl;
                    }
                    flowLastActivity_.erase(activityEntry);
                    streamingFlowIt = streamingFlows_.erase(streamingFlowIt);
                    continue;
                }
            }
            ++streamingFlowIt;
        }
    } else {
        // Cleanup traditional flows
        auto flowIt = flows_.begin();
        
        while (flowIt != flows_.end()) {
            const uint64_t& flowId = flowIt->first;
            auto activityEntry = flowLastActivity_.find(flowId);
            
            if (activityEntry != flowLastActivity_.end()) {
                double timeSinceLastActivity = currentTime - activityEntry->second;
                
                // Remove flows that have been inactive for longer than flow timeout
                if (timeSinceLastActivity > config_.flowTimeout) {
                    if (config_.verbose) {
                        std::cout << "Cleaning up expired flow: " << flowId << std::endl;
                    }
                    flowLastActivity_.erase(activityEntry);
                    flowIt = flows_.erase(flowIt);
                    continue;
                }
            }
            ++flowIt;
        }
    }
}

void FlowFeatureExtractor::periodicCleanup(double currentTime) {
    cleanupExpiredFlows(currentTime);
    
    if (config_.verbose) {
        size_t memUsage = getMemoryUsage();
        size_t activeFlows = config_.enableStreaming ? streamingFlows_.size() : flows_.size();
        std::string mode = config_.enableStreaming ? "streaming" : "traditional";
        std::cout << "Memory cleanup (" << mode << "): " << activeFlows << " active flows, "
                  << "~" << memUsage / (1024 * 1024) << " MB estimated usage" << std::endl;
    }
}

size_t FlowFeatureExtractor::getMemoryUsage() const {
    size_t totalMemory = 0;
    
    if (config_.enableStreaming) {
        // Memory usage for streaming flows (much lower)
        for (const auto& flowPair : streamingFlows_) {
            const StreamingFlow& flow = flowPair.second;
            
            // Base StreamingFlow structure
            totalMemory += sizeof(StreamingFlow);
            
            // Recent packets buffer (limited size)
            size_t packetInfoSize = sizeof(double) +     // timestamp
                                   sizeof(uint16_t) * 5 + // length, srcPort, dstPort, headerLength, payloadLength
                                   sizeof(uint32_t) * 2 + // srcIpHash, dstIpHash
                                   sizeof(uint8_t) * 4 +  // protocol, tcpFlags, icmpCode, icmpType
                                   sizeof(uint16_t) +     // windowSize
                                   64 + 64 +             // srcIp, dstIp strings (estimated)
                                   200;                   // flags map (estimated)
            
            totalMemory += flow.recentPackets.size() * packetInfoSize;
            totalMemory += flow.recentIsForward.size() * sizeof(bool);
            
            // Inter-arrival time vectors
            totalMemory += flow.fwdInterArrivalTimes.size() * sizeof(double);
            totalMemory += flow.bwdInterArrivalTimes.size() * sizeof(double);
            
            totalMemory += sizeof(uint64_t); // Flow ID hash
        }
    } else {
        // Traditional flow memory usage
        for (const auto& flowPair : flows_) {
            const Flow& flow = flowPair.second;
            
            // Memory for optimized packet storage (no duplication)
            // Calculate actual PacketInfo memory usage with optimized fields
            size_t packetInfoSize = sizeof(double) +     // timestamp
                                   sizeof(uint16_t) * 5 + // length, srcPort, dstPort, headerLength, payloadLength
                                   sizeof(uint32_t) * 2 + // srcIpHash, dstIpHash
                                   sizeof(uint8_t) * 4 +  // protocol, tcpFlags, icmpCode, icmpType
                                   sizeof(uint16_t) +     // windowSize
                                   64 + 64 +             // srcIp, dstIp strings (estimated)
                                   200;                   // flags map (estimated)
            
            totalMemory += flow.packets.size() * packetInfoSize;
            totalMemory += flow.isForward.size() * sizeof(bool); // Direction flags
            
            // Memory for other flow data structures
            totalMemory += sizeof(Flow);
            totalMemory += sizeof(uint64_t); // Flow ID hash
        }
    }
    
    // Memory for activity tracking
    totalMemory += flowLastActivity_.size() * (sizeof(uint64_t) + sizeof(double));
    
    return totalMemory;
}

// Helper functions for optimized packet access
std::vector<PacketInfo> FlowFeatureExtractor::getForwardPackets(const Flow& flow) const {
    std::vector<PacketInfo> fwdPackets;
    fwdPackets.reserve(flow.fwdPacketCount);
    
    for (size_t i = 0; i < flow.packets.size(); ++i) {
        if (flow.isForward[i]) {
            fwdPackets.push_back(flow.packets[i]);
        }
    }
    
    return fwdPackets;
}

std::vector<PacketInfo> FlowFeatureExtractor::getBackwardPackets(const Flow& flow) const {
    std::vector<PacketInfo> bwdPackets;
    bwdPackets.reserve(flow.bwdPacketCount);
    
    for (size_t i = 0; i < flow.packets.size(); ++i) {
        if (!flow.isForward[i]) {
            bwdPackets.push_back(flow.packets[i]);
        }
    }
    
    return bwdPackets;
}

uint32_t FlowFeatureExtractor::hashIpAddress(const std::string& ip) const {
    std::hash<std::string> hasher;
    return static_cast<uint32_t>(hasher(ip));
}

void FlowFeatureExtractor::processPacketStreaming(pcpp::Packet& packet) {
    PacketInfo pktInfo = extractPacketInfo(packet);
    uint64_t flowId = getFlowId(pktInfo.srcIp, pktInfo.dstIp, pktInfo.srcPort, pktInfo.dstPort, pktInfo.protocol);
    
    // Determine packet direction
    bool isForward = true;
    auto flowIt = streamingFlows_.find(flowId);
    if (flowIt != streamingFlows_.end()) {
        const StreamingFlow& existingFlow = flowIt->second;
        isForward = (pktInfo.srcIp == existingFlow.srcIp && pktInfo.srcPort == existingFlow.srcPort);
    }
    
    // Create or update streaming flow
    if (flowIt == streamingFlows_.end()) {
        StreamingFlow newFlow;
        newFlow.srcIp = pktInfo.srcIp;
        newFlow.dstIp = pktInfo.dstIp;
        newFlow.srcPort = pktInfo.srcPort;
        newFlow.dstPort = pktInfo.dstPort;
        newFlow.protocol = pktInfo.protocol;
        newFlow.startTime = pktInfo.timestamp;
        streamingFlows_[flowId] = newFlow;
        flowIt = streamingFlows_.find(flowId);
    }
    
    updateStreamingFlow(flowIt->second, pktInfo, isForward);
    flowLastActivity_[flowId] = pktInfo.timestamp;
    
    // Extract features in real-time if enabled
    if (config_.streamingRealTime) {
        FlowFeatures features = extractStreamingFlowFeatures(flowId, flowIt->second);
        // Features can be output or processed immediately
    }
}

void FlowFeatureExtractor::updateStreamingFlow(StreamingFlow& flow, const PacketInfo& packet, bool isForward) {
    flow.endTime = packet.timestamp;
    
    if (isForward) {
        flow.fwdPacketCount++;
        flow.fwdTotalBytes += packet.length;
        flow.fwdHeaderBytes += packet.headerLength;
        
        // Update length statistics
        if (packet.length < flow.fwdMinLength) flow.fwdMinLength = packet.length;
        if (packet.length > flow.fwdMaxLength) flow.fwdMaxLength = packet.length;
        flow.fwdLengthSum += packet.length;
        flow.fwdLengthSumSquares += packet.length * packet.length;
        
        // Update timing
        if (flow.lastFwdTime > 0) {
            double interArrival = packet.timestamp - flow.lastFwdTime;
            flow.fwdInterArrivalTimes.push_back(interArrival);
        }
        flow.lastFwdTime = packet.timestamp;
        
        // TCP flags
        if (packet.tcpFlags.psh) flow.fwdPshFlags++;
        if (packet.tcpFlags.urg) flow.fwdUrgFlags++;
        flow.fwdWindowSizeSum += packet.windowSize;
    } else {
        flow.bwdPacketCount++;
        flow.bwdTotalBytes += packet.length;
        flow.bwdHeaderBytes += packet.headerLength;
        
        // Update length statistics
        if (packet.length < flow.bwdMinLength) flow.bwdMinLength = packet.length;
        if (packet.length > flow.bwdMaxLength) flow.bwdMaxLength = packet.length;
        flow.bwdLengthSum += packet.length;
        flow.bwdLengthSumSquares += packet.length * packet.length;
        
        // Update timing
        if (flow.lastBwdTime > 0) {
            double interArrival = packet.timestamp - flow.lastBwdTime;
            flow.bwdInterArrivalTimes.push_back(interArrival);
        }
        flow.lastBwdTime = packet.timestamp;
        
        // TCP flags
        if (packet.tcpFlags.psh) flow.bwdPshFlags++;
        if (packet.tcpFlags.urg) flow.bwdUrgFlags++;
        flow.bwdWindowSizeSum += packet.windowSize;
    }
    
    // Maintain limited packet buffer for advanced statistics
    flow.recentPackets.push_back(packet);
    flow.recentIsForward.push_back(isForward);
    
    // Keep buffer size limited
    while (flow.recentPackets.size() > static_cast<size_t>(config_.streamingBufferSize)) {
        flow.recentPackets.pop_front();
        flow.recentIsForward.pop_front();
    }
}

FlowFeatures FlowFeatureExtractor::extractStreamingFlowFeatures(uint64_t flowId, const StreamingFlow& flow) {
    FlowFeatures features;
    features.flowId = std::to_string(flowId);
    features.srcIp = flow.srcIp;
    features.dstIp = flow.dstIp;
    features.srcPort = flow.srcPort;
    features.dstPort = flow.dstPort;
    features.protocol = flow.protocol;
    
    // Basic packet counts and bytes
    features.fwdPacketCount = flow.fwdPacketCount;
    features.bwdPacketCount = flow.bwdPacketCount;
    features.fwdTotalBytes = flow.fwdTotalBytes;
    features.bwdTotalBytes = flow.bwdTotalBytes;
    
    // Length statistics
    if (flow.fwdPacketCount > 0) {
        features.fwdPacketLengthMean = flow.fwdLengthSum / flow.fwdPacketCount;
        features.fwdPacketLengthMin = flow.fwdMinLength;
        features.fwdPacketLengthMax = flow.fwdMaxLength;
        
        if (flow.fwdPacketCount > 1) {
            double variance = (flow.fwdLengthSumSquares / flow.fwdPacketCount) - 
                            (features.fwdPacketLengthMean * features.fwdPacketLengthMean);
            features.fwdPacketLengthStd = std::sqrt(std::max(0.0, variance));
        }
    }
    
    if (flow.bwdPacketCount > 0) {
        features.bwdPacketLengthMean = flow.bwdLengthSum / flow.bwdPacketCount;
        features.bwdPacketLengthMin = flow.bwdMinLength;
        features.bwdPacketLengthMax = flow.bwdMaxLength;
        
        if (flow.bwdPacketCount > 1) {
            double variance = (flow.bwdLengthSumSquares / flow.bwdPacketCount) - 
                            (features.bwdPacketLengthMean * features.bwdPacketLengthMean);
            features.bwdPacketLengthStd = std::sqrt(std::max(0.0, variance));
        }
    }
    
    // Inter-arrival time statistics
    if (!flow.fwdInterArrivalTimes.empty()) {
        double sum = std::accumulate(flow.fwdInterArrivalTimes.begin(), flow.fwdInterArrivalTimes.end(), 0.0);
        features.fwdIATMean = sum / flow.fwdInterArrivalTimes.size();
        features.fwdIATMin = *std::min_element(flow.fwdInterArrivalTimes.begin(), flow.fwdInterArrivalTimes.end());
        features.fwdIATMax = *std::max_element(flow.fwdInterArrivalTimes.begin(), flow.fwdInterArrivalTimes.end());
    }
    
    if (!flow.bwdInterArrivalTimes.empty()) {
        double sum = std::accumulate(flow.bwdInterArrivalTimes.begin(), flow.bwdInterArrivalTimes.end(), 0.0);
        features.bwdIATMean = sum / flow.bwdInterArrivalTimes.size();
        features.bwdIATMin = *std::min_element(flow.bwdInterArrivalTimes.begin(), flow.bwdInterArrivalTimes.end());
        features.bwdIATMax = *std::max_element(flow.bwdInterArrivalTimes.begin(), flow.bwdInterArrivalTimes.end());
    }
    
    // Flow duration
    features.flowDuration = flow.endTime - flow.startTime;
    
    // TCP flags
    features.fwdPshFlags = flow.fwdPshFlags;
    features.bwdPshFlags = flow.bwdPshFlags;
    features.fwdUrgFlags = flow.fwdUrgFlags;
    features.bwdUrgFlags = flow.bwdUrgFlags;
    
    return features;
}

// FeatureGroups static method implementations
std::set<std::string> FeatureGroups::getFeaturesByGroup(const std::string& groupName) {
    if (groupName == "basic") return BASIC;
    if (groupName == "timing") return TIMING;
    if (groupName == "flags") return FLAGS;
    if (groupName == "bulk") return BULK;
    if (groupName == "window") return WINDOW;
    if (groupName == "retransmission") return RETRANSMISSION;
    if (groupName == "icmp") return ICMP;
    if (groupName == "statistics") return STATISTICS;
    if (groupName == "all") return getAllFeatureNames();
    return {};
}

std::set<std::string> FeatureGroups::getAllFeatureNames() {
    std::set<std::string> allFeatures;
    
    // Combine all feature groups
    for (const auto& feature : BASIC) allFeatures.insert(feature);
    for (const auto& feature : TIMING) allFeatures.insert(feature);
    for (const auto& feature : FLAGS) allFeatures.insert(feature);
    for (const auto& feature : BULK) allFeatures.insert(feature);
    for (const auto& feature : WINDOW) allFeatures.insert(feature);
    for (const auto& feature : RETRANSMISSION) allFeatures.insert(feature);
    for (const auto& feature : ICMP) allFeatures.insert(feature);
    for (const auto& feature : STATISTICS) allFeatures.insert(feature);
    
    return allFeatures;
}

bool FeatureGroups::isValidFeatureName(const std::string& featureName) {
    std::set<std::string> allFeatures = getAllFeatureNames();
    return allFeatures.find(featureName) != allFeatures.end();
}

bool FeatureGroups::isValidGroupName(const std::string& groupName) {
    return groupName == "basic" || groupName == "timing" || groupName == "flags" ||
           groupName == "bulk" || groupName == "window" || groupName == "retransmission" ||
           groupName == "icmp" || groupName == "statistics" || groupName == "all";
}

// FlowFeatureExtractor feature selection helper methods
std::set<std::string> FlowFeatureExtractor::resolveSelectedFeatures() const {
    std::set<std::string> selectedFeatures;
    
    // If specific features are enabled, use those
    if (!config_.enabledFeatures.empty()) {
        selectedFeatures = config_.enabledFeatures;
    } else {
        // Otherwise, use feature groups
        for (const auto& groupName : config_.enabledFeatureGroups) {
            std::set<std::string> groupFeatures = FeatureGroups::getFeaturesByGroup(groupName);
            selectedFeatures.insert(groupFeatures.begin(), groupFeatures.end());
        }
    }
    
    // Remove disabled features
    for (const auto& disabledFeature : config_.disabledFeatures) {
        selectedFeatures.erase(disabledFeature);
    }
    
    return selectedFeatures;
}

std::vector<std::string> FlowFeatureExtractor::getCSVHeader(const std::set<std::string>& selectedFeatures) const {
    std::vector<std::string> header;
    
    // Define the order of features as they appear in the original CSV
    std::vector<std::string> allFeatureOrder = {
        "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
        "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
        "Total Length of Fwd Packet", "Total Length of Bwd Packet",
        "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
        "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd RST Flags", "Bwd RST Flags",
        "Fwd Header Length", "Bwd Header Length",
        "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
        "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count",
        "Down/Up Ratio", "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg",
        "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg", "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg",
        "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
        "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts", "Bwd Act Data Pkts", "Fwd Seg Size Min", "Bwd Seg Size Min",
        "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
        "ICMP Code", "ICMP Type", "Fwd TCP Retrans. Count", "Bwd TCP Retrans. Count", "Total TCP Retrans. Count", "Total Connection Flow Time"
    };
    
    // Add features in the correct order
    for (const auto& feature : allFeatureOrder) {
        if (selectedFeatures.find(feature) != selectedFeatures.end()) {
            header.push_back(feature);
        }
    }
    
    return header;
}

std::string FlowFeatureExtractor::getFeatureValue(const FlowFeatures& feature, const std::string& featureName) const {
    if (featureName == "Flow ID") return feature.flowId;
    if (featureName == "Src IP") return feature.srcIp;
    if (featureName == "Src Port") return std::to_string(feature.srcPort);
    if (featureName == "Dst IP") return feature.dstIp;
    if (featureName == "Dst Port") return std::to_string(feature.dstPort);
    if (featureName == "Protocol") return std::to_string(static_cast<int>(feature.protocol));
    if (featureName == "Timestamp") return feature.timestamp;
    if (featureName == "Flow Duration") return std::to_string(feature.flowDuration);
    if (featureName == "Total Fwd Packet") return std::to_string(feature.totalFwdPackets);
    if (featureName == "Total Bwd packets") return std::to_string(feature.totalBwdPackets);
    if (featureName == "Total Length of Fwd Packet") return std::to_string(feature.totalLengthFwdPackets);
    if (featureName == "Total Length of Bwd Packet") return std::to_string(feature.totalLengthBwdPackets);
    if (featureName == "Fwd Packet Length Max") return std::to_string(feature.fwdPacketLengthMax);
    if (featureName == "Fwd Packet Length Min") return std::to_string(feature.fwdPacketLengthMin);
    if (featureName == "Fwd Packet Length Mean") return std::to_string(feature.fwdPacketLengthMean);
    if (featureName == "Fwd Packet Length Std") return std::to_string(feature.fwdPacketLengthStd);
    if (featureName == "Bwd Packet Length Max") return std::to_string(feature.bwdPacketLengthMax);
    if (featureName == "Bwd Packet Length Min") return std::to_string(feature.bwdPacketLengthMin);
    if (featureName == "Bwd Packet Length Mean") return std::to_string(feature.bwdPacketLengthMean);
    if (featureName == "Bwd Packet Length Std") return std::to_string(feature.bwdPacketLengthStd);
    if (featureName == "Flow Bytes/s") return std::to_string(feature.flowBytesPerSec);
    if (featureName == "Flow Packets/s") return std::to_string(feature.flowPacketsPerSec);
    if (featureName == "Fwd Packets/s") return std::to_string(feature.fwdPacketsPerSec);
    if (featureName == "Bwd Packets/s") return std::to_string(feature.bwdPacketsPerSec);
    if (featureName == "Flow IAT Mean") return std::to_string(feature.flowIATMean);
    if (featureName == "Flow IAT Std") return std::to_string(feature.flowIATStd);
    if (featureName == "Flow IAT Max") return std::to_string(feature.flowIATMax);
    if (featureName == "Flow IAT Min") return std::to_string(feature.flowIATMin);
    if (featureName == "Fwd IAT Total") return std::to_string(feature.fwdIATTotal);
    if (featureName == "Fwd IAT Mean") return std::to_string(feature.fwdIATMean);
    if (featureName == "Fwd IAT Std") return std::to_string(feature.fwdIATStd);
    if (featureName == "Fwd IAT Max") return std::to_string(feature.fwdIATMax);
    if (featureName == "Fwd IAT Min") return std::to_string(feature.fwdIATMin);
    if (featureName == "Bwd IAT Total") return std::to_string(feature.bwdIATTotal);
    if (featureName == "Bwd IAT Mean") return std::to_string(feature.bwdIATMean);
    if (featureName == "Bwd IAT Std") return std::to_string(feature.bwdIATStd);
    if (featureName == "Bwd IAT Max") return std::to_string(feature.bwdIATMax);
    if (featureName == "Bwd IAT Min") return std::to_string(feature.bwdIATMin);
    if (featureName == "Fwd PSH Flags") return std::to_string(feature.fwdPSHFlags);
    if (featureName == "Bwd PSH Flags") return std::to_string(feature.bwdPSHFlags);
    if (featureName == "Fwd URG Flags") return std::to_string(feature.fwdURGFlags);
    if (featureName == "Bwd URG Flags") return std::to_string(feature.bwdURGFlags);
    if (featureName == "Fwd RST Flags") return std::to_string(feature.fwdRSTFlags);
    if (featureName == "Bwd RST Flags") return std::to_string(feature.bwdRSTFlags);
    if (featureName == "Fwd Header Length") return std::to_string(feature.fwdHeaderLength);
    if (featureName == "Bwd Header Length") return std::to_string(feature.bwdHeaderLength);
    if (featureName == "Packet Length Min") return std::to_string(feature.packetLengthMin);
    if (featureName == "Packet Length Max") return std::to_string(feature.packetLengthMax);
    if (featureName == "Packet Length Mean") return std::to_string(feature.packetLengthMean);
    if (featureName == "Packet Length Std") return std::to_string(feature.packetLengthStd);
    if (featureName == "Packet Length Variance") return std::to_string(feature.packetLengthVariance);
    if (featureName == "FIN Flag Count") return std::to_string(feature.finFlagCount);
    if (featureName == "SYN Flag Count") return std::to_string(feature.synFlagCount);
    if (featureName == "RST Flag Count") return std::to_string(feature.rstFlagCount);
    if (featureName == "PSH Flag Count") return std::to_string(feature.pshFlagCount);
    if (featureName == "ACK Flag Count") return std::to_string(feature.ackFlagCount);
    if (featureName == "URG Flag Count") return std::to_string(feature.urgFlagCount);
    if (featureName == "CWR Flag Count") return std::to_string(feature.cwrFlagCount);
    if (featureName == "ECE Flag Count") return std::to_string(feature.eceFlagCount);
    if (featureName == "Down/Up Ratio") return std::to_string(feature.downUpRatio);
    if (featureName == "Average Packet Size") return std::to_string(feature.averagePacketSize);
    if (featureName == "Fwd Segment Size Avg") return std::to_string(feature.fwdSegmentSizeAvg);
    if (featureName == "Bwd Segment Size Avg") return std::to_string(feature.bwdSegmentSizeAvg);
    if (featureName == "Fwd Bytes/Bulk Avg") return std::to_string(feature.fwdBytesBulkAvg);
    if (featureName == "Fwd Packet/Bulk Avg") return std::to_string(feature.fwdPacketBulkAvg);
    if (featureName == "Fwd Bulk Rate Avg") return std::to_string(feature.fwdBulkRateAvg);
    if (featureName == "Bwd Bytes/Bulk Avg") return std::to_string(feature.bwdBytesBulkAvg);
    if (featureName == "Bwd Packet/Bulk Avg") return std::to_string(feature.bwdPacketBulkAvg);
    if (featureName == "Bwd Bulk Rate Avg") return std::to_string(feature.bwdBulkRateAvg);
    if (featureName == "Subflow Fwd Packets") return std::to_string(feature.subflowFwdPackets);
    if (featureName == "Subflow Fwd Bytes") return std::to_string(feature.subflowFwdBytes);
    if (featureName == "Subflow Bwd Packets") return std::to_string(feature.subflowBwdPackets);
    if (featureName == "Subflow Bwd Bytes") return std::to_string(feature.subflowBwdBytes);
    if (featureName == "FWD Init Win Bytes") return std::to_string(feature.fwdInitWinBytes);
    if (featureName == "Bwd Init Win Bytes") return std::to_string(feature.bwdInitWinBytes);
    if (featureName == "Fwd Act Data Pkts") return std::to_string(feature.fwdActDataPkts);
    if (featureName == "Bwd Act Data Pkts") return std::to_string(feature.bwdActDataPkts);
    if (featureName == "Fwd Seg Size Min") return std::to_string(feature.fwdSegSizeMin);
    if (featureName == "Bwd Seg Size Min") return std::to_string(feature.bwdSegSizeMin);
    if (featureName == "Active Mean") return std::to_string(feature.activeMean);
    if (featureName == "Active Std") return std::to_string(feature.activeStd);
    if (featureName == "Active Max") return std::to_string(feature.activeMax);
    if (featureName == "Active Min") return std::to_string(feature.activeMin);
    if (featureName == "Idle Mean") return std::to_string(feature.idleMean);
    if (featureName == "Idle Std") return std::to_string(feature.idleStd);
    if (featureName == "Idle Max") return std::to_string(feature.idleMax);
    if (featureName == "Idle Min") return std::to_string(feature.idleMin);
    if (featureName == "ICMP Code") return std::to_string(static_cast<int>(feature.icmpCode));
    if (featureName == "ICMP Type") return std::to_string(static_cast<int>(feature.icmpType));
    if (featureName == "Fwd TCP Retrans. Count") return std::to_string(feature.fwdTCPRetransCount);
    if (featureName == "Bwd TCP Retrans. Count") return std::to_string(feature.bwdTCPRetransCount);
    if (featureName == "Total TCP Retrans. Count") return std::to_string(feature.totalTCPRetransCount);
    if (featureName == "Total Connection Flow Time") return std::to_string(feature.totalConnectionFlowTime);
    
    // New features
    if (featureName == "Fwd/Bwd Packet Ratio") return std::to_string(feature.fwdBwdPacketRatio);
    if (featureName == "Fwd/Bwd Byte Ratio") return std::to_string(feature.fwdBwdByteRatio);
    if (featureName == "Average Packet Rate") return std::to_string(feature.averagePacketRate);
    if (featureName == "Payload Entropy") return std::to_string(feature.payloadEntropy);
    if (featureName == "Header Entropy") return std::to_string(feature.headerEntropy);
    if (featureName == "Application Protocol") return feature.applicationProtocol;
    if (featureName == "TLS Certificate Count") return std::to_string(feature.tlsCertificateCount);
    if (featureName == "TLS Session ID Length") return std::to_string(feature.tlsSessionIdLength);
    if (featureName == "TLS Cipher Suite") return feature.tlsCipherSuite;
    if (featureName == "Burstiness") return std::to_string(feature.burstiness);
    if (featureName == "Packet Inter-Arrival Jitter") return std::to_string(feature.packetInterArrivalJitter);
    if (featureName == "Direction Change Count") return std::to_string(feature.directionChangeCount);
    if (featureName == "Average Idle Time") return std::to_string(feature.averageIdleTime);
    if (featureName == "Flow Persistence") return std::to_string(feature.flowPersistence);
    if (featureName == "Internal/External Flag") return feature.isInternalExternal ? "1" : "0";
    if (featureName == "Port Category") return feature.portCategory;
    if (featureName == "Packet Length Skewness") return std::to_string(feature.packetLengthSkewness);
    if (featureName == "Packet Length Kurtosis") return std::to_string(feature.packetLengthKurtosis);
    if (featureName == "IAT Skewness") return std::to_string(feature.iatSkewness);
    if (featureName == "IAT Kurtosis") return std::to_string(feature.iatKurtosis);
    
    return "0"; // Default value for unknown features
}

// Helper functions for new feature calculations
double FlowFeatureExtractor::calculatePayloadEntropy(const std::vector<PacketInfo>& packets) {
    std::map<uint8_t, int> byteFreq;
    int totalBytes = 0;
    
    // Count byte frequencies in payload (simplified - using packet length as proxy)
    for (const auto& packet : packets) {
        if (packet.payloadLength > 0) {
            // Simplified entropy calculation using payload length distribution
            uint8_t lengthByte = static_cast<uint8_t>(packet.payloadLength % 256);
            byteFreq[lengthByte]++;
            totalBytes++;
        }
    }
    
    if (totalBytes == 0) return 0.0;
    
    double entropy = 0.0;
    for (const auto& pair : byteFreq) {
        double probability = static_cast<double>(pair.second) / totalBytes;
        if (probability > 0) {
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

double FlowFeatureExtractor::calculateHeaderEntropy(const std::vector<PacketInfo>& packets) {
    std::map<uint16_t, int> headerFreq;
    int totalPackets = 0;
    
    // Count header length frequencies
    for (const auto& packet : packets) {
        headerFreq[packet.headerLength]++;
        totalPackets++;
    }
    
    if (totalPackets == 0) return 0.0;
    
    double entropy = 0.0;
    for (const auto& pair : headerFreq) {
        double probability = static_cast<double>(pair.second) / totalPackets;
        if (probability > 0) {
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

std::string FlowFeatureExtractor::detectApplicationProtocol(const Flow& flow) {
    // Simple protocol detection based on port numbers
    uint16_t minPort = std::min(flow.srcPort, flow.dstPort);
    uint16_t maxPort = std::max(flow.srcPort, flow.dstPort);
    
    if (flow.protocol == 6) { // TCP
        if (minPort == 80 || maxPort == 80) return "HTTP";
        if (minPort == 443 || maxPort == 443) return "HTTPS";
        if (minPort == 21 || maxPort == 21) return "FTP";
        if (minPort == 22 || maxPort == 22) return "SSH";
        if (minPort == 23 || maxPort == 23) return "Telnet";
        if (minPort == 25 || maxPort == 25) return "SMTP";
        if (minPort == 110 || maxPort == 110) return "POP3";
        if (minPort == 143 || maxPort == 143) return "IMAP";
        if (minPort == 993 || maxPort == 993) return "IMAPS";
        if (minPort == 995 || maxPort == 995) return "POP3S";
    } else if (flow.protocol == 17) { // UDP
        if (minPort == 53 || maxPort == 53) return "DNS";
        if (minPort == 67 || maxPort == 67 || minPort == 68 || maxPort == 68) return "DHCP";
        if (minPort == 123 || maxPort == 123) return "NTP";
        if (minPort == 161 || maxPort == 161) return "SNMP";
        if (minPort == 5683 || maxPort == 5683) return "CoAP";
    }
    
    return "Unknown";
}

std::pair<int, int> FlowFeatureExtractor::extractTLSFeatures(const std::vector<PacketInfo>& packets) {
    // Simplified TLS feature extraction
    // In a real implementation, this would parse TLS handshake packets
    int certCount = 0;
    int sessionIdLength = 0;
    
    // Look for potential TLS handshake patterns
    for (const auto& packet : packets) {
        if (packet.payloadLength > 5) {
            // Simplified heuristic for TLS detection
            if (packet.payloadLength > 100) {
                certCount = 1; // Assume certificate present in large packets
                sessionIdLength = 32; // Typical session ID length
            }
        }
    }
    
    return std::make_pair(certCount, sessionIdLength);
}

double FlowFeatureExtractor::calculateBurstiness(const std::vector<PacketInfo>& packets) {
    if (packets.size() < 2) return 0.0;
    
    std::vector<double> intervals;
    for (size_t i = 1; i < packets.size(); ++i) {
        intervals.push_back(packets[i].timestamp - packets[i-1].timestamp);
    }
    
    if (intervals.empty()) return 0.0;
    
    double mean = std::accumulate(intervals.begin(), intervals.end(), 0.0) / intervals.size();
    double variance = 0.0;
    
    for (double interval : intervals) {
        variance += (interval - mean) * (interval - mean);
    }
    variance /= intervals.size();
    
    // Burstiness index: (variance - mean) / (variance + mean)
    if (variance + mean == 0) return 0.0;
    return (variance - mean) / (variance + mean);
}

double FlowFeatureExtractor::calculateJitter(const std::vector<PacketInfo>& packets) {
    if (packets.size() < 3) return 0.0;
    
    std::vector<double> intervals;
    for (size_t i = 1; i < packets.size(); ++i) {
        intervals.push_back(packets[i].timestamp - packets[i-1].timestamp);
    }
    
    if (intervals.size() < 2) return 0.0;
    
    double jitter = 0.0;
    for (size_t i = 1; i < intervals.size(); ++i) {
        jitter += std::abs(intervals[i] - intervals[i-1]);
    }
    
    return jitter / (intervals.size() - 1);
}

int FlowFeatureExtractor::calculateDirectionChanges(const Flow& flow) {
    if (flow.isForward.size() < 2) return 0;
    
    int changes = 0;
    for (size_t i = 1; i < flow.isForward.size(); ++i) {
        if (flow.isForward[i] != flow.isForward[i-1]) {
            changes++;
        }
    }
    
    return changes;
}

double FlowFeatureExtractor::calculateFlowPersistence(const std::vector<PacketInfo>& packets, double duration) {
    if (packets.empty() || duration <= 0) return 0.0;
    
    // Flow persistence as the ratio of active time to total time
    // Simplified: assume flow is active when packets are being sent
    double activeTime = 0.0;
    const double activeWindow = 1.0; // 1 second window
    
    if (packets.size() < 2) return duration > 0 ? 1.0 : 0.0;
    
    // Count time windows with activity
    double currentTime = packets[0].timestamp;
    double endTime = packets.back().timestamp;
    
    while (currentTime < endTime) {
        bool hasActivity = false;
        for (const auto& packet : packets) {
            if (packet.timestamp >= currentTime && packet.timestamp < currentTime + activeWindow) {
                hasActivity = true;
                break;
            }
        }
        if (hasActivity) activeTime += activeWindow;
        currentTime += activeWindow;
    }
    
    return duration > 0 ? activeTime / duration : 0.0;
}

bool FlowFeatureExtractor::isInternalTraffic(const std::string& srcIp, const std::string& dstIp) {
    // Simple internal/external classification based on private IP ranges
    auto isPrivateIP = [](const std::string& ip) {
        // Check for private IP ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        if (ip.substr(0, 3) == "10.") return true;
        if (ip.substr(0, 8) == "192.168.") return true;
        if (ip.substr(0, 4) == "172.") {
            size_t pos = ip.find('.', 4);
            if (pos != std::string::npos) {
                int second = std::stoi(ip.substr(4, pos - 4));
                if (second >= 16 && second <= 31) return true;
            }
        }
        return false;
    };
    
    return isPrivateIP(srcIp) && isPrivateIP(dstIp);
}

std::string FlowFeatureExtractor::categorizePort(uint16_t srcPort, uint16_t dstPort) {
    uint16_t minPort = std::min(srcPort, dstPort);
    
    if (minPort <= 1023) return "well-known";
    if (minPort <= 49151) return "registered";
    return "dynamic";
}

double FlowFeatureExtractor::calculateSkewness(const std::vector<double>& values) {
    if (values.size() < 3) return 0.0;
    
    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    double variance = 0.0;
    double skewness = 0.0;
    
    for (double value : values) {
        double diff = value - mean;
        variance += diff * diff;
        skewness += diff * diff * diff;
    }
    
    variance /= values.size();
    skewness /= values.size();
    
    double stdDev = std::sqrt(variance);
    if (stdDev == 0) return 0.0;
    
    return skewness / (stdDev * stdDev * stdDev);
}

double FlowFeatureExtractor::calculateKurtosis(const std::vector<double>& values) {
    if (values.size() < 4) return 0.0;
    
    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    double variance = 0.0;
    double kurtosis = 0.0;
    
    for (double value : values) {
        double diff = value - mean;
        variance += diff * diff;
        kurtosis += diff * diff * diff * diff;
    }
    
    variance /= values.size();
    kurtosis /= values.size();
    
    if (variance == 0) return 0.0;
    
    return (kurtosis / (variance * variance)) - 3.0; // Excess kurtosis
}

void FlowFeatureExtractor::exportSelectiveCSV(const std::vector<FlowFeatures>& features, 
                                             const std::string& outputFile,
                                             const std::set<std::string>& selectedFeatures) {
    if (features.empty()) {
        std::cout << "No features to export" << std::endl;
        return;
    }
    
    std::ofstream file(outputFile);
    if (!file.is_open()) {
        std::cerr << "Cannot open output file: " << outputFile << std::endl;
        return;
    }
    
    // Get ordered header
    std::vector<std::string> header = getCSVHeader(selectedFeatures);
    
    // Write CSV header
    for (size_t i = 0; i < header.size(); ++i) {
        file << header[i];
        if (i < header.size() - 1) file << ",";
    }
    file << "\n";
    
    // Write data rows
    for (const auto& feature : features) {
        for (size_t i = 0; i < header.size(); ++i) {
            file << getFeatureValue(feature, header[i]);
            if (i < header.size() - 1) file << ",";
        }
        file << "\n";
    }
    
    file.close();
    std::cout << "Selective flow features exported to: " << outputFile << std::endl;
    std::cout << "Total flows exported: " << features.size() << std::endl;
    std::cout << "Features included: " << selectedFeatures.size() << " out of " << FeatureGroups::getAllFeatureNames().size() << std::endl;
}