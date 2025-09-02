#include "flow_analyzer.h"
#include <iostream>
#include <string>
#include <filesystem>
#include <cstring>
#include <sstream>
#include <vector>

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <pcap_file> [options]\n\n";
    std::cout << "Extract flow features from PCAP files using PcapPlusPlus\n\n";
    std::cout << "Positional arguments:\n";
    std::cout << "  pcap_file             Input PCAP file path\n\n";
    std::cout << "Optional arguments:\n";
    std::cout << "  -o, --output FILE     Output CSV file path (default: flow_features.csv)\n";
    std::cout << "  -c, --config MODE     Configuration mode:\n";
    std::cout << "                        - default: Standard feature extraction (recommended)\n";
    std::cout << "                        - high_performance: Faster processing, reduced features\n";
    std::cout << "                        - detailed_analysis: All features enabled, slower processing\n";
    std::cout << "                        - real_time: Optimized for real-time analysis\n";
    std::cout << "  -v, --verbose         Enable verbose output\n";
    std::cout << "  --show-config         Show configuration and exit\n";
    std::cout << "  --max-flows NUM       Maximum number of flows to process\n";
    std::cout << "  --features LIST       Comma-separated list of specific features to include\n";
    std::cout << "  --feature-groups LIST Comma-separated list of feature groups to include\n";
    std::cout << "                        Available groups: basic, timing, flags, bulk, window,\n";
    std::cout << "                        retransmission, icmp, statistics, ratios, entropy,\n";
    std::cout << "                        protocol, behavioral, network, higher_order\n";
    std::cout << "  --exclude-features LIST Comma-separated list of features to exclude\n";
    std::cout << "  -h, --help            Show this help message and exit\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << programName << " traffic.pcap\n";
    std::cout << "  " << programName << " traffic.pcap -o results.csv --config detailed_analysis\n";
    std::cout << "  " << programName << " traffic.pcap --config high_performance --verbose\n";
    std::cout << "  " << programName << " traffic.pcap --feature-groups basic,timing\n";
    std::cout << "  " << programName << " traffic.pcap --features \"Flow ID,Src IP,Protocol\"\n";
    std::cout << "  " << programName << " traffic.pcap --feature-groups basic --exclude-features \"Flow Duration\"\n\n";
    std::cout << "Configuration modes:\n";
    std::cout << "  default          - Standard feature extraction (recommended)\n";
    std::cout << "  high_performance - Faster processing, reduced features\n";
    std::cout << "  detailed_analysis- All features enabled, slower processing\n";
    std::cout << "  real_time        - Optimized for real-time analysis\n";
}

struct Arguments {
    std::string pcapFile;
    std::string outputFile = "flow_features.csv";
    std::string configMode = "default";
    bool verbose = false;
    bool showConfig = false;
    int maxFlows = -1;
    bool help = false;
    std::string features = "";
    std::string featureGroups = "";
    std::string excludeFeatures = "";
    bool useSelectiveOutput = false;
};

Arguments parseArguments(int argc, char* argv[]) {
    Arguments args;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            args.help = true;
            return args;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                args.outputFile = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a value\n";
                args.help = true;
                return args;
            }
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                args.configMode = argv[++i];
                if (args.configMode != "default" && args.configMode != "high_performance" &&
                    args.configMode != "detailed_analysis" && args.configMode != "real_time") {
                    std::cerr << "Error: Invalid config mode '" << args.configMode << "'\n";
                    args.help = true;
                    return args;
                }
            } else {
                std::cerr << "Error: " << arg << " requires a value\n";
                args.help = true;
                return args;
            }
        } else if (arg == "-v" || arg == "--verbose") {
            args.verbose = true;
        } else if (arg == "--show-config") {
            args.showConfig = true;
        } else if (arg == "--max-flows") {
            if (i + 1 < argc) {
                try {
                    args.maxFlows = std::stoi(argv[++i]);
                    if (args.maxFlows <= 0) {
                        std::cerr << "Error: max-flows must be a positive integer\n";
                        args.help = true;
                        return args;
                    }
                } catch (const std::exception&) {
                    std::cerr << "Error: Invalid value for max-flows\n";
                    args.help = true;
                    return args;
                }
            } else {
                std::cerr << "Error: " << arg << " requires a value\n";
                args.help = true;
                return args;
            }
        } else if (arg == "--features") {
            if (i + 1 < argc) {
                args.features = argv[++i];
                args.useSelectiveOutput = true;
            } else {
                std::cerr << "Error: " << arg << " requires a value\n";
                args.help = true;
                return args;
            }
        } else if (arg == "--feature-groups") {
            if (i + 1 < argc) {
                args.featureGroups = argv[++i];
                args.useSelectiveOutput = true;
            } else {
                std::cerr << "Error: " << arg << " requires a value\n";
                args.help = true;
                return args;
            }
        } else if (arg == "--exclude-features") {
            if (i + 1 < argc) {
                args.excludeFeatures = argv[++i];
                args.useSelectiveOutput = true;
            } else {
                std::cerr << "Error: " << arg << " requires a value\n";
                args.help = true;
                return args;
            }
        } else if (arg[0] == '-') {
            std::cerr << "Error: Unknown option '" << arg << "'\n";
            args.help = true;
            return args;
        } else {
            if (args.pcapFile.empty()) {
                args.pcapFile = arg;
            } else {
                std::cerr << "Error: Multiple PCAP files specified\n";
                args.help = true;
                return args;
            }
        }
    }
    
    if (args.pcapFile.empty() && !args.showConfig && !args.help) {
        std::cerr << "Error: PCAP file is required\n";
        args.help = true;
    }
    
    return args;
}

std::vector<std::string> parseCommaSeparatedList(const std::string& input) {
    std::vector<std::string> result;
    std::stringstream ss(input);
    std::string item;
    
    while (std::getline(ss, item, ',')) {
        // Trim whitespace
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    
    return result;
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    Arguments args = parseArguments(argc, argv);
    
    if (args.help) {
        printUsage(argv[0]);
        return args.help && args.pcapFile.empty() ? 1 : 0;
    }
    
    // Get configuration
    Config config = getConfig(args.configMode);
    
    // Override max flows if specified
    if (args.maxFlows > 0) {
        config.maxFlowPackets = args.maxFlows;
    }
    
    // Configure feature selection if specified
    if (args.useSelectiveOutput) {
        config.useSelectiveOutput = true;
        
        // Parse feature groups
        if (!args.featureGroups.empty()) {
            std::vector<std::string> groups = parseCommaSeparatedList(args.featureGroups);
            config.enabledFeatureGroups.insert(groups.begin(), groups.end());
        }
        
        // Parse specific features
        if (!args.features.empty()) {
            std::vector<std::string> features = parseCommaSeparatedList(args.features);
            config.enabledFeatures.insert(features.begin(), features.end());
        }
        
        // Parse excluded features
        if (!args.excludeFeatures.empty()) {
            std::vector<std::string> excludedFeatures = parseCommaSeparatedList(args.excludeFeatures);
            config.disabledFeatures.insert(excludedFeatures.begin(), excludedFeatures.end());
        }
    }
    
    // Show configuration if requested
    if (args.showConfig) {
        printConfig(config);
        return 0;
    }
    
    // Validate configuration
    if (!validateConfig(config)) {
        std::cerr << "Invalid configuration" << std::endl;
        return 1;
    }
    
    // Check if input file exists
    if (!std::filesystem::exists(args.pcapFile)) {
        std::cerr << "Error: PCAP file '" << args.pcapFile << "' not found" << std::endl;
        return 1;
    }
    
    if (args.verbose) {
        std::cout << "Using configuration mode: " << args.configMode << std::endl;
        std::cout << "Input file: " << args.pcapFile << std::endl;
        std::cout << "Output file: " << args.outputFile << std::endl;
        std::cout << "\nConfiguration:" << std::endl;
        printConfig(config);
        std::cout << std::endl;
    }
    
    try {
        // Initialize feature extractor with configuration
        FlowFeatureExtractor extractor(config);
        
        // Analyze PCAP file
        std::vector<FlowFeatures> features = extractor.analyzePcap(args.pcapFile);
        
        if (!features.empty()) {
            // Export to CSV
            extractor.exportToCSV(features, args.outputFile);
            
            if (args.verbose) {
                std::cout << "\nAnalysis Summary:" << std::endl;
                std::cout << "  Total flows processed: " << features.size() << std::endl;
                std::cout << "  Features per flow: 89+" << std::endl;
                std::cout << "  Output saved to: " << args.outputFile << std::endl;
            }
        } else {
            std::cerr << "Failed to extract features" << std::endl;
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}