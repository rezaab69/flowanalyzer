#include "flow_analyzer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <chrono>
#include <numeric>

using namespace Tins;

FlowFeatureExtractor::FlowFeatureExtractor(const Config& config) : config_(config) {
    // Initialize with provided configuration
}

std::string FlowFeatureExtractor::getFlowId(const std::string& srcIp, const std::string& dstIp,
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
    
    // Simple hash function (in production, use proper hash like MD5)
    std::hash<std::string> hasher;
    size_t hashValue = hasher(flowTuple);
    
    std::stringstream ss;
    ss << std::hex << hashValue;
    return ss.str().substr(0, 16);
}

bool FlowFeatureExtractor::isForwardDirection(const std::string& srcIp, const std::string& /* dstIp */,
                                            uint16_t srcPort, uint16_t /* dstPort */,
                                            const std::string& flowSrcIp, uint16_t flowSrcPort) {
    return srcIp == flowSrcIp && srcPort == flowSrcPort;
}

PacketInfo FlowFeatureExtractor::extractPacketInfo(const PDU& pdu) {
    PacketInfo info;
    info.timestamp = 0.0; // PDU doesn't have timestamp, will need to be set externally
    info.length = pdu.size();
    info.headerLength = 0;
    info.payloadLength = 0;
    
    // Extract IP layer information
    const IP* ip = pdu.find_pdu<IP>();
    if (ip) {
        info.srcIp = ip->src_addr().to_string();
        info.dstIp = ip->dst_addr().to_string();
        info.protocol = ip->protocol();
        info.headerLength += ip->header_size();
    }
    
    // Extract TCP layer information
    const TCP* tcp = pdu.find_pdu<TCP>();
    if (tcp) {
        info.srcPort = tcp->sport();
        info.dstPort = tcp->dport();
        info.protocol = 6; // TCP
        info.headerLength += tcp->header_size();
        info.windowSize = tcp->window();
        
        // Extract TCP flags
        info.flags["FIN"] = tcp->flags() & TCP::FIN;
        info.flags["SYN"] = tcp->flags() & TCP::SYN;
        info.flags["RST"] = tcp->flags() & TCP::RST;
        info.flags["PSH"] = tcp->flags() & TCP::PSH;
        info.flags["ACK"] = tcp->flags() & TCP::ACK;
        info.flags["URG"] = tcp->flags() & TCP::URG;
        info.flags["CWR"] = tcp->flags() & TCP::CWR;
        info.flags["ECE"] = tcp->flags() & TCP::ECE;
    }
    
    // Extract UDP layer information
    const UDP* udp = pdu.find_pdu<UDP>();
    if (udp) {
        info.srcPort = udp->sport();
        info.dstPort = udp->dport();
        info.protocol = 17; // UDP
        info.headerLength += 8; // UDP header length
    }
    
    // Extract ICMP layer information
    const ICMP* icmp = pdu.find_pdu<ICMP>();
    if (icmp) {
        info.protocol = 1; // ICMP
        info.srcPort = 0;
        info.dstPort = 0;
        info.icmpCode = icmp->code();
        info.icmpType = icmp->type();
    }
    
    info.payloadLength = info.length - info.headerLength;
    return info;
}

void FlowFeatureExtractor::processPacket(const PDU& pdu) {
    try {
        PacketInfo pktInfo = extractPacketInfo(pdu);
        
        if (pktInfo.srcIp.empty() || pktInfo.dstIp.empty()) {
            return;
        }
        
        std::string flowId = getFlowId(pktInfo.srcIp, pktInfo.dstIp,
                                      pktInfo.srcPort, pktInfo.dstPort, pktInfo.protocol);
        
        Flow& flow = flows_[flowId];
        
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
        
        if (isForward) {
            flow.fwdPackets.push_back(pktInfo);
            // Update forward flags
            for (const auto& flag : pktInfo.flags) {
                if (flow.fwdFlags.find(flag.first) != flow.fwdFlags.end() && flag.second) {
                    flow.fwdFlags[flag.first]++;
                }
            }
        } else {
            flow.bwdPackets.push_back(pktInfo);
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

FlowFeatures FlowFeatureExtractor::extractFlowFeatures(const std::string& flowId, const Flow& flow) {
    FlowFeatures features;
    
    // Basic flow information
    features.flowId = flowId;
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
    
    // Packet counts
    features.totalFwdPackets = flow.fwdPackets.size();
    features.totalBwdPackets = flow.bwdPackets.size();
    
    // Calculate packet length statistics
    std::vector<double> fwdLengths, bwdLengths, allLengths;
    for (const auto& p : flow.fwdPackets) fwdLengths.push_back(p.length);
    for (const auto& p : flow.bwdPackets) bwdLengths.push_back(p.length);
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
        features.fwdPacketsPerSec = flow.fwdPackets.size() / duration;
        features.bwdPacketsPerSec = flow.bwdPackets.size() / duration;
    } else {
        features.flowBytesPerSec = 0;
        features.flowPacketsPerSec = 0;
        features.fwdPacketsPerSec = 0;
        features.bwdPacketsPerSec = 0;
    }
    
    // Inter-arrival times
    Statistics flowIAT = calculateIAT(flow.packets);
    Statistics fwdIAT = calculateIAT(flow.fwdPackets);
    Statistics bwdIAT = calculateIAT(flow.bwdPackets);
    
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
    for (const auto& p : flow.fwdPackets) fwdHeaderLength += p.headerLength;
    for (const auto& p : flow.bwdPackets) bwdHeaderLength += p.headerLength;
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
    for (const auto& p : flow.fwdPackets) {
        if (p.payloadLength > 0) fwdPayloads.push_back(p.payloadLength);
    }
    for (const auto& p : flow.bwdPackets) {
        if (p.payloadLength > 0) bwdPayloads.push_back(p.payloadLength);
    }
    
    features.fwdSegmentSizeAvg = fwdPayloads.empty() ? 0 : 
        std::accumulate(fwdPayloads.begin(), fwdPayloads.end(), 0.0) / fwdPayloads.size();
    features.bwdSegmentSizeAvg = bwdPayloads.empty() ? 0 : 
        std::accumulate(bwdPayloads.begin(), bwdPayloads.end(), 0.0) / bwdPayloads.size();
    
    // Bulk transfer features
    auto fwdBulk = calculateBulkFeatures(flow.fwdPackets);
    auto bwdBulk = calculateBulkFeatures(flow.bwdPackets);
    
    features.fwdBytesBulkAvg = fwdBulk.first / std::max(1, static_cast<int>(flow.fwdPackets.size()));
    features.fwdPacketBulkAvg = fwdBulk.second / std::max(1, static_cast<int>(flow.fwdPackets.size()));
    features.fwdBulkRateAvg = duration > 0 ? fwdBulk.first / duration : 0;
    features.bwdBytesBulkAvg = bwdBulk.first / std::max(1, static_cast<int>(flow.bwdPackets.size()));
    features.bwdPacketBulkAvg = bwdBulk.second / std::max(1, static_cast<int>(flow.bwdPackets.size()));
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
    int fwdRetrans = detectRetransmissions(flow.fwdPackets);
    int bwdRetrans = detectRetransmissions(flow.bwdPackets);
    
    features.fwdTCPRetransCount = fwdRetrans;
    features.bwdTCPRetransCount = bwdRetrans;
    features.totalTCPRetransCount = fwdRetrans + bwdRetrans;
    
    // Total connection flow time
    features.totalConnectionFlowTime = features.flowDuration;
    
    return features;
}

std::vector<FlowFeatures> FlowFeatureExtractor::analyzePcap(const std::string& pcapFile) {
    std::cout << "Analyzing PCAP file: " << pcapFile << std::endl;
    
    std::vector<FlowFeatures> flowFeatures;
    
    try {
        FileSniffer sniffer(pcapFile);
        int packetCount = 0;
        
        for (const auto& packet : sniffer) {
            // Extract PDU and timestamp from packet
            const PDU& pdu = *packet.pdu();
            double timestamp = packet.timestamp().seconds() + packet.timestamp().microseconds() / 1000000.0;
            
            // Process packet with timestamp
            PacketInfo pktInfo = extractPacketInfo(pdu);
            pktInfo.timestamp = timestamp;
            
            if (!pktInfo.srcIp.empty() && !pktInfo.dstIp.empty()) {
                // Process the packet info directly
                std::string flowId = getFlowId(pktInfo.srcIp, pktInfo.dstIp,
                                              pktInfo.srcPort, pktInfo.dstPort, pktInfo.protocol);
                
                Flow& flow = flows_[flowId];
                
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
                
                if (isForward) {
                    flow.fwdPackets.push_back(pktInfo);
                    // Update forward flags
                    for (const auto& flag : pktInfo.flags) {
                        if (flow.fwdFlags.find(flag.first) != flow.fwdFlags.end() && flag.second) {
                            flow.fwdFlags[flag.first]++;
                        }
                    }
                } else {
                    flow.bwdPackets.push_back(pktInfo);
                    // Update backward flags
                    for (const auto& flag : pktInfo.flags) {
                        if (flow.bwdFlags.find(flag.first) != flow.bwdFlags.end() && flag.second) {
                            flow.bwdFlags[flag.first]++;
                        }
                    }
                }
            }
            
            packetCount++;
            
            if (packetCount % 1000 == 0) {
                std::cout << "Processed " << packetCount << " packets..." << std::endl;
            }
        }
        
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
         << "ICMP Code,ICMP Type,Fwd TCP Retrans. Count,Bwd TCP Retrans. Count,Total TCP Retrans. Count,Total Connection Flow Time\n";
    
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
             << feature.totalTCPRetransCount << "," << feature.totalConnectionFlowTime << "\n";
    }
    
    file.close();
    std::cout << "Flow features exported to: " << outputFile << std::endl;
    std::cout << "Total flows exported: " << features.size() << std::endl;
}