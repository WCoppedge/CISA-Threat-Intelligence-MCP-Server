# CISA-Threat-Intelligence-MCP-Server
Use a MCP server to know about Cisa CVE's

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MCP Protocol](https://img.shields.io/badge/MCP-compatible-green.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> A production-ready Model Context Protocol (MCP) server providing AI agents with real-time access to CISA's Known Exploited Vulnerabilities (KEV) catalog and advanced threat intelligence capabilities.

## Overview

This MCP server enables AI assistants to perform sophisticated cybersecurity analysis by integrating with authoritative government data sources. Built specifically for cybersecurity professionals, government agencies, and security operations centers.

### Key Features

- **🔒 Real-Time CISA KEV Integration**: Direct access to 1,400+ actively exploited vulnerabilities
- **🧠 Advanced Threat Intelligence**: Custom scoring algorithms and trend analysis
- **🏛️ Government Compliance**: BOD 22-01 tracking and federal security requirements
- **🤖 AI Agent Ready**: Purpose-built for AI-powered security workflows
- **📊 Comprehensive Analytics**: Executive reporting and strategic insights

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Internet connectivity for CISA/NVD APIs
- MCP-compatible client (Claude Desktop, etc.)

### Installation

  1. Copy the code in the .py file into vs code save it as cisa_threat_intel_mcp.py
  2. Then add the path to the conf file it should be a .json file you can see a temp below
  3. restart Claude
  4. Now ask question

### Configuration

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "cisa-threat-intel": {
      "command": "python",
      "args": ["/path/to/cisa_threat_intel_mcp.py"],
      "env": {}
    }
  }
}
```

## 🛠️ Available Tools

### `search_kev_catalog`
Search and filter CISA's Known Exploited Vulnerabilities catalog.

**Example Usage:**
```
Find all Microsoft vulnerabilities with known ransomware usage added in the last 30 days
```

### `analyze_threat_trends`
Perform strategic threat intelligence analysis with pattern recognition.

**Analysis Types:**
- **Trending**: Vendor/product exploitation patterns
- **Critical**: High-impact vulnerability identification
- **Ransomware**: Campaign tracking and analysis
- **Recent**: Emerging threat detection

### `enrich_cve_intelligence`
Deep-dive CVE analysis with comprehensive threat scoring.

**Features:**
- CISA KEV metadata integration
- NVD enrichment with CVSS scores
- Custom threat scoring (0-100 scale)
- Strategic remediation recommendations

### `get_kev_statistics`
Executive-level statistics and strategic insights.

## 🏗️ Architecture

### Threat Scoring Algorithm
Sophisticated scoring system considering:
- KEV catalog inclusion (+50 base points)
- Ransomware campaign usage (+30 points)
- Recency of addition (+10-20 points)
- Vulnerability impact type (+5-25 points)
- CVSS severity scores (+5-15 points)

### Data Sources
- **Primary**: CISA KEV Catalog (real-time)
- **Enrichment**: NVD API for technical details
- **Compliance**: BOD 22-01 guidance integration

### Error Handling
- Graceful degradation when APIs unavailable
- Comprehensive input validation
- Detailed error messages with remediation guidance

## 📊 Usage Examples

### Daily Threat Briefing
```python
# Generate executive summary
statistics = await get_kev_statistics()
recent_threats = await search_kev_catalog(days_added=7)
critical_analysis = await analyze_threat_trends("critical", 30)
```

### Incident Response
```python
# Emergency CVE analysis
cve_intelligence = await enrich_cve_intelligence("CVE-2024-1234")
related_threats = await search_kev_catalog(vendor="Microsoft")
```

### Compliance Tracking
```python
# BOD 22-01 monitoring
upcoming_deadlines = await search_kev_catalog(days_added=21)
compliance_stats = await get_kev_statistics()
```

## 🛡️ Security Considerations

- **No Data Storage**: Stateless design with real-time API fetching
- **Input Validation**: Comprehensive Pydantic validation
- **Rate Limiting**: Respectful API usage patterns
- **Error Security**: Sanitized error messages

## 📈 Performance

- **Async Operations**: Full async/await implementation
- **Caching Strategy**: Intelligent response caching
- **Concurrent Processing**: Parallel API enrichment
- **Error Recovery**: Graceful fallback mechanisms

## 📜 License

This project is licensed under the MIT License 

## 🔗 Related Resources

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [BOD 22-01 Guidance](https://www.cisa.gov/binding-operational-directive-22-01)

## 📞 Contact

**Author**: Will Coppedge  
**Email**: wcoppedge7779@gmail.com  
**LinkedIn**: [LinkedIn Profile]  
**Portfolio**: [Portfolio Website]

---

> **Note**: This project demonstrates advanced cybersecurity automation, AI integration, and government data handling - perfect for federal cybersecurity roles and modern security operations.

## 🏆 Recognition

*This project showcases cutting-edge integration of AI agents with authoritative government cybersecurity data sources, demonstrating the future of automated threat intelligence.*
