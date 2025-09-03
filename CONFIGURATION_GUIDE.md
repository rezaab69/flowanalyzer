# Flow Analyzer Configuration Guide

This guide provides comprehensive information about configuring the Flow Analyzer for optimal performance and feature extraction.

## Table of Contents

1. [Configuration Overview](#configuration-overview)
2. [Configuration Presets](#configuration-presets)
3. [Configuration Parameters](#configuration-parameters)
4. [Feature Selection](#feature-selection)
5. [Command-Line Options](#command-line-options)
6. [Usage Examples](#usage-examples)
7. [Performance Tuning](#performance-tuning)
8. [Validation and Troubleshooting](#validation-and-troubleshooting)

## Configuration Overview

The Flow Analyzer uses a flexible configuration system that allows you to:
- Choose from predefined configuration presets
- Customize individual parameters
- Select specific features or feature groups
- Optimize for different use cases (performance vs. detail)

## Configuration Presets

The analyzer provides four built-in configuration presets:

### 1. Default Configuration (`default`)
**Recommended for most users**
- Balanced performance and feature completeness
- All detection features enabled
- Standard timeout and packet limits
- Suitable for general network analysis

### 2. High Performance Configuration (`high_performance`)
**Optimized for speed and large datasets**
- Reduced feature set for faster processing
- Lower precision calculations
- Optimized for bulk processing
- Best for real-time monitoring of high-traffic networks

### 3. Detailed Analysis Configuration (`detailed_analysis`)
**Maximum feature extraction**
- All features enabled
- Enhanced timing and statistical calculations
- Higher precision output
- Best for forensic analysis and research

### 4. Real-Time Configuration (`real_time`)
**Optimized for streaming analysis**
- Streaming processing enabled
- Reduced buffer sizes
- Real-time feature extraction
- Best for live network monitoring

## Configuration Parameters

### Bulk Transfer Detection
- **`bulkThreshold`** (int, default: 4): Minimum packets to classify as bulk transfer
- **`enableBulkDetection`** (bool, default: true): Enable/disable bulk transfer detection

### Active/Idle Time Detection
- **`activeThreshold`** (double, default: 1.0): Threshold in seconds for active/idle classification
- **`enableActiveIdle`** (bool, default: true): Enable/disable active/idle time calculation

### Retransmission Detection
- **`enableRetransDetection`** (bool, default: true): Enable/disable retransmission detection
- **`retransWindow`** (double, default: 0.1): Time window in seconds for retransmission detection

### Performance Settings
- **`maxFlowPackets`** (int, default: 10000): Maximum packets per flow before timeout
- **`flowTimeout`** (int, default: 3600): Flow timeout in seconds

### Feature Calculation Settings
- **`calculateVariance`** (bool, default: true): Calculate variance statistics
- **`detailedTiming`** (bool, default: true): Enable detailed timing calculations
- **`enhancedFlags`** (bool, default: true): Enable enhanced flag analysis

### Output Settings
- **`includeFlowId`** (bool, default: true): Include flow ID in output
- **`timestampFormat`** (string, default: "datetime"): Timestamp format ("datetime" or "unix")
- **`precision`** (int, default: 6): Decimal precision for floating-point values
- **`verbose`** (bool, default: false): Enable verbose output

### Streaming Processing Settings
- **`enableStreaming`** (bool, default: false): Process packets without storing them
- **`streamingBufferSize`** (int, default: 100): Number of packets to buffer for statistics
- **`streamingRealTime`** (bool, default: true): Extract features in real-time

## Feature Selection

### Feature Groups

The analyzer organizes features into logical groups:

- **`basic`**: Core flow information (IPs, ports, protocol)
- **`timing`**: Time-based features (duration, inter-arrival times)
- **`flags`**: TCP flag statistics
- **`bulk`**: Bulk transfer characteristics
- **`window`**: TCP window size statistics
- **`retransmission`**: Retransmission and duplicate detection
- **`icmp`**: ICMP-specific features
- **`statistics`**: Statistical measures (mean, std, min, max)
- **`ratios`**: Forward/backward ratios and rates
- **`entropy`**: Payload and header entropy measures
- **`protocol`**: Application protocol detection
- **`behavioral`**: Flow behavior patterns
- **`network`**: Network context features
- **`higher_order`**: Advanced statistical measures

### Feature Selection Options

- **`enabledFeatureGroups`**: Set of feature groups to include (default: {"all"})
- **`enabledFeatures`**: Set of individual features to include (overrides groups)
- **`disabledFeatures`**: Set of individual features to exclude
- **`useSelectiveOutput`**: Enable selective feature output

## Command-Line Options

### Basic Usage
```bash
flow_analyzer <pcap_file> [options]
```

### Configuration Options

| Option | Description | Example |
|--------|-------------|----------|
| `-c, --config MODE` | Set configuration preset | `--config high_performance` |
| `--show-config` | Display current configuration | `--show-config` |
| `--max-flows NUM` | Limit number of flows | `--max-flows 1000` |

### Output Options

| Option | Description | Example |
|--------|-------------|----------|
| `-o, --output FILE` | Output CSV file | `-o results.csv` |
| `-v, --verbose` | Enable verbose output | `--verbose` |

### Feature Selection Options

| Option | Description | Example |
|--------|-------------|----------|
| `--features LIST` | Specific features to include | `--features "Flow ID,Src IP,Protocol"` |
| `--feature-groups LIST` | Feature groups to include | `--feature-groups basic,timing` |
| `--exclude-features LIST` | Features to exclude | `--exclude-features "Flow Duration"` |

## Usage Examples

### Basic Analysis
```bash
# Use default configuration
flow_analyzer traffic.pcap

# Specify output file
flow_analyzer traffic.pcap -o analysis_results.csv
```

### Configuration Presets
```bash
# High-performance analysis
flow_analyzer large_traffic.pcap --config high_performance

# Detailed forensic analysis
flow_analyzer suspicious_traffic.pcap --config detailed_analysis --verbose

# Real-time monitoring setup
flow_analyzer live_capture.pcap --config real_time
```

### Feature Selection
```bash
# Select specific feature groups
flow_analyzer traffic.pcap --feature-groups basic,timing,statistics

# Select individual features
flow_analyzer traffic.pcap --features "Flow ID,Src IP,Dst IP,Protocol,Flow Duration"

# Exclude specific features
flow_analyzer traffic.pcap --feature-groups basic --exclude-features "Flow Duration,Idle Time"

# Combine groups and exclusions
flow_analyzer traffic.pcap --feature-groups basic,timing --exclude-features "Min IAT,Max IAT"
```

### Performance Optimization
```bash
# Limit flows for large files
flow_analyzer huge_traffic.pcap --max-flows 10000 --config high_performance

# Verbose analysis with configuration display
flow_analyzer traffic.pcap --config detailed_analysis --verbose --show-config
```

## Performance Tuning

### For Large Files
- Use `high_performance` preset
- Set `--max-flows` to limit processing
- Consider feature group selection instead of all features
- Disable detailed timing if not needed

### For Real-Time Analysis
- Use `real_time` preset
- Enable streaming processing
- Reduce buffer sizes
- Select essential feature groups only

### For Detailed Analysis
- Use `detailed_analysis` preset
- Enable all detection features
- Increase precision settings
- Allow longer processing times

### Memory Optimization
- Reduce `maxFlowPackets` for memory-constrained environments
- Use streaming mode for continuous processing
- Limit feature selection to reduce output size

## Validation and Troubleshooting

### Configuration Validation

The analyzer automatically validates:
- Parameter ranges and types
- Feature group names
- Individual feature names
- Logical consistency

### Common Issues

1. **Invalid Feature Names**
   - Check spelling and case sensitivity
   - Use `--show-config` to see available features
   - Refer to feature group definitions

2. **Performance Issues**
   - Try `high_performance` preset
   - Reduce feature selection
   - Limit flow count with `--max-flows`

3. **Memory Issues**
   - Reduce `maxFlowPackets`
   - Enable streaming mode
   - Process files in smaller chunks

4. **Output Issues**
   - Check file permissions for output directory
   - Verify CSV format compatibility
   - Use appropriate precision settings

### Debugging Commands

```bash
# Show current configuration
flow_analyzer --show-config

# Validate configuration with verbose output
flow_analyzer traffic.pcap --config detailed_analysis --verbose

# Test with minimal features
flow_analyzer traffic.pcap --feature-groups basic --verbose
```

### Getting Help

```bash
# Show help message
flow_analyzer --help

# Show configuration options
flow_analyzer --show-config
```

## Best Practices

1. **Start with Default**: Use the default configuration for initial analysis
2. **Profile First**: Test with small files before processing large datasets
3. **Select Wisely**: Choose appropriate feature groups for your use case
4. **Monitor Resources**: Watch memory and CPU usage during processing
5. **Validate Output**: Check results with known traffic patterns
6. **Document Settings**: Keep track of configuration used for reproducibility

This configuration system provides the flexibility to adapt the Flow Analyzer to various network analysis scenarios while maintaining optimal performance and accuracy.