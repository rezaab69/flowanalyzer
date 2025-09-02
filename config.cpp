#include "flow_analyzer.h"
#include <iostream>
#include <iomanip>

Config getDefaultConfig() {
    Config config;
    config.bulkThreshold = 4;
    config.enableBulkDetection = true;
    config.activeThreshold = 1.0;
    config.enableActiveIdle = true;
    config.enableRetransDetection = true;
    config.retransWindow = 0.1;
    config.maxFlowPackets = 10000;
    config.flowTimeout = 3600;
    config.calculateVariance = true;
    config.detailedTiming = true;
    config.enhancedFlags = true;
    config.includeFlowId = true;
    config.timestampFormat = "datetime";
    config.precision = 6;
    
    // Feature selection defaults
    config.useSelectiveOutput = false;
    config.enabledFeatureGroups.clear();
    config.enabledFeatures.clear();
    config.disabledFeatures.clear();
    
    return config;
}

Config getHighPerformanceConfig() {
    Config config;
    config.bulkThreshold = 8;
    config.enableBulkDetection = false;  // Disable for performance
    config.activeThreshold = 2.0;
    config.enableActiveIdle = false;  // Disable for performance
    config.enableRetransDetection = false;  // Disable for performance
    config.retransWindow = 0.1;
    config.maxFlowPackets = 5000;
    config.flowTimeout = 1800;
    config.calculateVariance = false;
    config.detailedTiming = false;
    config.enhancedFlags = false;
    config.includeFlowId = true;
    config.timestampFormat = "unix";
    config.precision = 3;
    
    // Feature selection defaults - basic features only for performance
    config.useSelectiveOutput = true;
    config.enabledFeatureGroups.insert("BASIC");
    config.enabledFeatureGroups.insert("TIMING");
    config.enabledFeatures.clear();
    config.disabledFeatures.clear();
    
    return config;
}

Config getDetailedAnalysisConfig() {
    Config config;
    config.bulkThreshold = 3;
    config.enableBulkDetection = true;
    config.activeThreshold = 0.5;
    config.enableActiveIdle = true;
    config.enableRetransDetection = true;
    config.retransWindow = 0.05;
    config.maxFlowPackets = 50000;
    config.flowTimeout = 7200;
    config.calculateVariance = true;
    config.detailedTiming = true;
    config.enhancedFlags = true;
    config.includeFlowId = true;
    config.timestampFormat = "datetime";
    config.precision = 8;
    
    // Feature selection defaults - all features for detailed analysis
    config.useSelectiveOutput = false;
    config.enabledFeatureGroups.clear();
    config.enabledFeatures.clear();
    config.disabledFeatures.clear();
    
    return config;
}

Config getRealTimeConfig() {
    Config config;
    config.bulkThreshold = 6;
    config.enableBulkDetection = true;
    config.activeThreshold = 1.5;
    config.enableActiveIdle = true;
    config.enableRetransDetection = true;
    config.retransWindow = 0.1;
    config.maxFlowPackets = 1000;
    config.flowTimeout = 300;  // 5 minutes
    config.calculateVariance = true;
    config.detailedTiming = false;
    config.enhancedFlags = true;
    config.includeFlowId = true;
    config.timestampFormat = "unix";
    config.precision = 4;
    
    // Feature selection defaults - essential features for real-time
    config.useSelectiveOutput = true;
    config.enabledFeatureGroups.insert("BASIC");
    config.enabledFeatureGroups.insert("TIMING");
    config.enabledFeatureGroups.insert("FLAGS");
    config.enabledFeatures.clear();
    config.disabledFeatures.clear();
    
    return config;
}

Config getConfig(const std::string& configName) {
    if (configName == "high_performance") {
        return getHighPerformanceConfig();
    } else if (configName == "detailed_analysis") {
        return getDetailedAnalysisConfig();
    } else if (configName == "real_time") {
        return getRealTimeConfig();
    } else {
        return getDefaultConfig();
    }
}

bool validateConfig(const Config& config) {
    if (config.bulkThreshold < 1) {
        std::cerr << "bulk_threshold must be >= 1" << std::endl;
        return false;
    }
    
    if (config.activeThreshold <= 0) {
        std::cerr << "active_threshold must be > 0" << std::endl;
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
    
    // Validate feature selection if enabled
    if (config.useSelectiveOutput) {
        // Validate feature groups
        for (const auto& group : config.enabledFeatureGroups) {
            if (!FeatureGroups::isValidGroupName(group)) {
                std::cerr << "Invalid feature group: " << group << std::endl;
                return false;
            }
        }
        
        // Validate individual features
        for (const auto& feature : config.enabledFeatures) {
            if (!FeatureGroups::isValidFeatureName(feature)) {
                std::cerr << "Invalid feature name: " << feature << std::endl;
                return false;
            }
        }
        
        for (const auto& feature : config.disabledFeatures) {
            if (!FeatureGroups::isValidFeatureName(feature)) {
                std::cerr << "Invalid disabled feature name: " << feature << std::endl;
                return false;
            }
        }
    }
    
    return true;
}

void printConfig(const Config& config) {
    std::cout << "Flow Feature Extractor Configuration:" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::cout << "\nBulk Transfer:" << std::endl;
    std::cout << "  bulk_threshold: " << config.bulkThreshold << std::endl;
    std::cout << "  enable_bulk_detection: " << (config.enableBulkDetection ? "true" : "false") << std::endl;
    
    std::cout << "\nActive/Idle:" << std::endl;
    std::cout << "  active_threshold: " << config.activeThreshold << std::endl;
    std::cout << "  enable_active_idle: " << (config.enableActiveIdle ? "true" : "false") << std::endl;
    
    std::cout << "\nRetransmission:" << std::endl;
    std::cout << "  enable_retrans_detection: " << (config.enableRetransDetection ? "true" : "false") << std::endl;
    std::cout << "  retrans_window: " << config.retransWindow << std::endl;
    
    std::cout << "\nPerformance:" << std::endl;
    std::cout << "  max_flow_packets: " << config.maxFlowPackets << std::endl;
    std::cout << "  flow_timeout: " << config.flowTimeout << std::endl;
    
    std::cout << "\nFeatures:" << std::endl;
    std::cout << "  calculate_variance: " << (config.calculateVariance ? "true" : "false") << std::endl;
    std::cout << "  detailed_timing: " << (config.detailedTiming ? "true" : "false") << std::endl;
    std::cout << "  enhanced_flags: " << (config.enhancedFlags ? "true" : "false") << std::endl;
    
    std::cout << "\nOutput:" << std::endl;
    std::cout << "  include_flow_id: " << (config.includeFlowId ? "true" : "false") << std::endl;
    std::cout << "  timestamp_format: " << config.timestampFormat << std::endl;
    std::cout << "  precision: " << config.precision << std::endl;
    
    std::cout << "\nFeature Selection:" << std::endl;
    std::cout << "  use_selective_output: " << (config.useSelectiveOutput ? "true" : "false") << std::endl;
    
    if (config.useSelectiveOutput) {
        if (!config.enabledFeatureGroups.empty()) {
            std::cout << "  enabled_feature_groups: ";
            bool first = true;
            for (const auto& group : config.enabledFeatureGroups) {
                if (!first) std::cout << ", ";
                std::cout << group;
                first = false;
            }
            std::cout << std::endl;
        }
        
        if (!config.enabledFeatures.empty()) {
            std::cout << "  enabled_features: ";
            bool first = true;
            for (const auto& feature : config.enabledFeatures) {
                if (!first) std::cout << ", ";
                std::cout << feature;
                first = false;
            }
            std::cout << std::endl;
        }
        
        if (!config.disabledFeatures.empty()) {
            std::cout << "  disabled_features: ";
            bool first = true;
            for (const auto& feature : config.disabledFeatures) {
                if (!first) std::cout << ", ";
                std::cout << feature;
                first = false;
            }
            std::cout << std::endl;
        }
    }
}