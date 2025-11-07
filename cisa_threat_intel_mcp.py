#!/usr/bin/env python3
"""
CISA Threat Intelligence MCP Server

A comprehensive MCP server providing AI agents with access to CISA's Known Exploited 
Vulnerabilities (KEV) catalog and enriched threat intelligence data. This server enables
advanced vulnerability management, threat hunting, and security analysis workflows.

Perfect for: CISA analysts, federal agencies, cybersecurity teams, threat hunters
Author: Built for government cybersecurity applications
Version: 1.0.0
"""

import json
import asyncio
from typing import Optional, List, Dict, Any, Literal
from enum import Enum
from datetime import datetime, timedelta
import httpx
from pydantic import BaseModel, Field, ConfigDict, field_validator
from mcp.server.fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("cisa_threat_intel_mcp")

# Constants
CHARACTER_LIMIT = 25000
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class ResponseFormat(str, Enum):
    """Output format options for responses."""
    MARKDOWN = "markdown"
    JSON = "json"

class ThreatLevel(str, Enum):
    """Threat severity levels for analysis."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class VulnerabilityType(str, Enum):
    """Common vulnerability types for filtering."""
    RCE = "Remote Code Execution"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    AUTHENTICATION_BYPASS = "Authentication Bypass"
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    INFORMATION_DISCLOSURE = "Information Disclosure"

# Shared utility functions for code reusability
async def fetch_cisa_kev_data() -> Dict[str, Any]:
    """Fetch the latest CISA KEV catalog data."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(CISA_KEV_URL)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Failed to fetch CISA KEV data: {e.response.status_code} - {e.response.text}")
        except httpx.TimeoutException:
            raise ValueError("CISA KEV API request timed out. Please try again.")

async def enrich_cve_with_nvd(cve_id: str) -> Dict[str, Any]:
    """Enrich CVE data with additional NVD information."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            params = {"cveId": cve_id}
            response = await client.get(NVD_API_BASE, params=params)
            response.raise_for_status()
            data = response.json()
            
            if data.get("vulnerabilities"):
                return data["vulnerabilities"][0]["cve"]
            return {}
            
        except Exception:
            # If NVD enrichment fails, continue without it
            return {}

def calculate_threat_score(vulnerability: Dict[str, Any], nvd_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Calculate a threat score based on vulnerability characteristics."""
    score = 0
    factors = []
    
    # Base score for being in KEV catalog
    score += 50
    factors.append("Listed in CISA KEV catalog")
    
    # Ransomware usage adds significant weight
    if vulnerability.get("knownRansomwareCampaignUse") == "Known":
        score += 30
        factors.append("Known ransomware campaign usage")
    
    # Recent additions are higher priority
    date_added = datetime.strptime(vulnerability.get("dateAdded", "2020-01-01"), "%Y-%m-%d")
    days_since_added = (datetime.now() - date_added).days
    if days_since_added <= 30:
        score += 20
        factors.append("Recently added to KEV (last 30 days)")
    elif days_since_added <= 90:
        score += 10
        factors.append("Recently added to KEV (last 90 days)")
    
    # Check for high-impact vulnerability types
    vuln_name = vulnerability.get("vulnerabilityName", "").lower()
    description = vulnerability.get("shortDescription", "").lower()
    
    if any(term in vuln_name or term in description for term in ["remote code execution", "rce"]):
        score += 25
        factors.append("Remote Code Execution capability")
    
    if any(term in vuln_name or term in description for term in ["privilege escalation", "escalation"]):
        score += 20
        factors.append("Privilege escalation vulnerability")
    
    if any(term in vuln_name or term in description for term in ["authentication bypass", "bypass"]):
        score += 15
        factors.append("Authentication bypass vulnerability")
    
    # Add NVD CVSS score if available
    if nvd_data and "metrics" in nvd_data:
        cvss_data = nvd_data["metrics"]
        if "cvssMetricV31" in cvss_data or "cvssMetricV3" in cvss_data:
            cvss_metrics = cvss_data.get("cvssMetricV31", cvss_data.get("cvssMetricV3", []))
            if cvss_metrics:
                base_score = cvss_metrics[0]["cvssData"]["baseScore"]
                if base_score >= 9.0:
                    score += 15
                    factors.append(f"CVSS 3.x Critical ({base_score})")
                elif base_score >= 7.0:
                    score += 10
                    factors.append(f"CVSS 3.x High ({base_score})")
                elif base_score >= 4.0:
                    score += 5
                    factors.append(f"CVSS 3.x Medium ({base_score})")
    
    # Determine threat level
    if score >= 80:
        threat_level = ThreatLevel.CRITICAL
    elif score >= 60:
        threat_level = ThreatLevel.HIGH
    elif score >= 40:
        threat_level = ThreatLevel.MEDIUM
    else:
        threat_level = ThreatLevel.LOW
    
    return {
        "threat_score": min(score, 100),  # Cap at 100
        "threat_level": threat_level.value,
        "scoring_factors": factors
    }

def format_vulnerability_data(vulnerabilities: List[Dict], format_type: ResponseFormat, 
                            include_threat_scores: bool = False) -> str:
    """Shared formatting function for vulnerability data."""
    if not vulnerabilities:
        return "No vulnerabilities found matching the criteria."
    
    if format_type == ResponseFormat.JSON:
        return json.dumps(vulnerabilities, indent=2)
    
    # Markdown format
    output = f"## CISA Threat Intelligence Report\n\n"
    output += f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}\n"
    output += f"**Vulnerabilities Found:** {len(vulnerabilities)}\n\n"
    
    for i, vuln in enumerate(vulnerabilities[:20], 1):  # Show first 20
        output += f"### {i}. {vuln.get('vulnerabilityName', 'Unknown Vulnerability')}\n"
        output += f"- **CVE ID:** {vuln.get('cveID', 'N/A')}\n"
        output += f"- **Vendor/Product:** {vuln.get('vendorProject', 'Unknown')} / {vuln.get('product', 'Unknown')}\n"
        output += f"- **Date Added:** {vuln.get('dateAdded', 'Unknown')}\n"
        output += f"- **Due Date:** {vuln.get('dueDate', 'Unknown')}\n"
        output += f"- **Ransomware Use:** {vuln.get('knownRansomwareCampaignUse', 'Unknown')}\n"
        
        if include_threat_scores and 'threat_analysis' in vuln:
            threat = vuln['threat_analysis']
            output += f"- **🚨 Threat Level:** {threat['threat_level'].upper()} (Score: {threat['threat_score']}/100)\n"
            if threat['scoring_factors']:
                output += f"- **Risk Factors:** {', '.join(threat['scoring_factors'][:3])}\n"
        
        # Truncate long descriptions
        description = vuln.get('shortDescription', 'No description available')
        if len(description) > 200:
            description = description[:200] + "..."
        output += f"- **Description:** {description}\n"
        
        output += f"- **Required Action:** {vuln.get('requiredAction', 'See vendor guidance')}\n\n"
    
    if len(vulnerabilities) > 20:
        output += f"*Showing first 20 of {len(vulnerabilities)} total results. Use JSON format for complete data.*\n"
    
    return output

def truncate_response(response: str, data_count: int) -> str:
    """Shared truncation utility."""
    if len(response) > CHARACTER_LIMIT:
        truncated = response[:CHARACTER_LIMIT - 300]
        truncated += f"\n\n**[RESPONSE TRUNCATED]**\n"
        truncated += f"Response too large ({len(response)} chars). Showing partial data from {data_count} records.\n"
        truncated += f"**Recommendations:**\n"
        truncated += f"- Use more specific filters to reduce results\n"
        truncated += f"- Request JSON format for programmatic processing\n"
        truncated += f"- Focus on recent or high-priority vulnerabilities\n"
        return truncated
    return response

# Input validation models using Pydantic

class KEVSearchInput(BaseModel):
    """Input model for searching CISA KEV catalog."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra='forbid')
    
    vendor: Optional[str] = Field(
        default=None,
        description="Filter by vendor/project (e.g., 'Microsoft', 'Cisco', 'Apache')",
        max_length=100
    )
    product: Optional[str] = Field(
        default=None,
        description="Filter by product name (e.g., 'Windows', 'Exchange', 'Chrome')",
        max_length=100
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="Specific CVE ID to lookup (e.g., 'CVE-2024-1234')",
        pattern=r"^CVE-\d{4}-\d{4,}$"
    )
    ransomware_use: Optional[bool] = Field(
        default=None,
        description="Filter by known ransomware campaign usage (true/false)"
    )
    days_added: Optional[int] = Field(
        default=None,
        description="Show vulnerabilities added in last N days (1-365)",
        ge=1, le=365
    )
    include_enrichment: bool = Field(
        default=False,
        description="Include additional NVD enrichment data (slower but more detailed)"
    )
    limit: int = Field(
        default=50,
        description="Maximum results to return (1-200)",
        ge=1, le=200
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable"
    )

class ThreatAnalysisInput(BaseModel):
    """Input model for threat analysis operations."""
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    
    analysis_type: Literal["trending", "critical", "ransomware", "recent"] = Field(
        description="Type of analysis: 'trending' (patterns), 'critical' (high-impact), 'ransomware' (campaigns), 'recent' (latest additions)"
    )
    time_period: int = Field(
        default=30,
        description="Analysis time period in days (7-365)",
        ge=7, le=365
    )
    vendor_focus: Optional[str] = Field(
        default=None,
        description="Focus analysis on specific vendor (e.g., 'Microsoft', 'Google')",
        max_length=100
    )
    include_predictions: bool = Field(
        default=False,
        description="Include threat predictions and recommendations"
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format preference"
    )

class CVEEnrichmentInput(BaseModel):
    """Input model for CVE enrichment operations."""
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    
    cve_id: str = Field(
        description="CVE ID to enrich (e.g., 'CVE-2024-1234')",
        pattern=r"^CVE-\d{4}-\d{4,}$"
    )
    include_threat_analysis: bool = Field(
        default=True,
        description="Include threat scoring and analysis"
    )
    include_nvd_data: bool = Field(
        default=True,
        description="Include additional NVD vulnerability data"
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format preference"
    )

# MCP Tools - each tool enables a complete cybersecurity workflow

@mcp.tool(
    name="search_kev_catalog",
    annotations={
        "title": "Search CISA KEV Catalog",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def search_kev_catalog(params: KEVSearchInput) -> str:
    """Search and filter CISA's Known Exploited Vulnerabilities catalog.
    
    This tool provides access to CISA's authoritative catalog of vulnerabilities
    that have been exploited in the wild. Essential for vulnerability management,
    threat hunting, and security prioritization workflows.
    
    Args:
        params (KEVSearchInput): Search parameters containing:
            - vendor (Optional[str]): Filter by vendor/project name
            - product (Optional[str]): Filter by product name
            - cve_id (Optional[str]): Lookup specific CVE ID (CVE-YYYY-NNNN format)
            - ransomware_use (Optional[bool]): Filter by ransomware campaign usage
            - days_added (Optional[int]): Recently added vulnerabilities (1-365 days)
            - include_enrichment (bool): Include NVD enrichment (slower, more detailed)
            - limit (int): Maximum results (1-200, default 50)
            - response_format (ResponseFormat): 'markdown' or 'json'
    
    Returns:
        str: Filtered vulnerability data with CISA metadata, threat indicators,
             remediation guidance, and optional NVD enrichment data.
    """
    try:
        # Fetch latest KEV data
        kev_data = await fetch_cisa_kev_data()
        vulnerabilities = kev_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return "No vulnerabilities found in CISA KEV catalog. Please try again later."
        
        # Apply filters
        filtered_vulns = vulnerabilities
        
        # CVE ID filter (exact match)
        if params.cve_id:
            filtered_vulns = [v for v in filtered_vulns if v.get("cveID", "").upper() == params.cve_id.upper()]
        
        # Vendor filter (case-insensitive partial match)
        if params.vendor:
            vendor_lower = params.vendor.lower()
            filtered_vulns = [v for v in filtered_vulns 
                            if vendor_lower in v.get("vendorProject", "").lower()]
        
        # Product filter (case-insensitive partial match)  
        if params.product:
            product_lower = params.product.lower()
            filtered_vulns = [v for v in filtered_vulns 
                            if product_lower in v.get("product", "").lower()]
        
        # Ransomware usage filter
        if params.ransomware_use is not None:
            if params.ransomware_use:
                filtered_vulns = [v for v in filtered_vulns 
                                if v.get("knownRansomwareCampaignUse") == "Known"]
            else:
                filtered_vulns = [v for v in filtered_vulns 
                                if v.get("knownRansomwareCampaignUse") != "Known"]
        
        # Recent additions filter
        if params.days_added:
            cutoff_date = datetime.now() - timedelta(days=params.days_added)
            filtered_vulns = [v for v in filtered_vulns 
                            if datetime.strptime(v.get("dateAdded", "2020-01-01"), "%Y-%m-%d") >= cutoff_date]
        
        # Limit results
        filtered_vulns = filtered_vulns[:params.limit]
        
        # Enrich with NVD data if requested
        if params.include_enrichment:
            for vuln in filtered_vulns:
                nvd_data = await enrich_cve_with_nvd(vuln.get("cveID", ""))
                if nvd_data:
                    vuln["nvd_enrichment"] = nvd_data
                
                # Add threat analysis
                vuln["threat_analysis"] = calculate_threat_score(vuln, nvd_data)
        
        # Format response
        result = format_vulnerability_data(
            filtered_vulns, 
            params.response_format,
            include_threat_scores=params.include_enrichment
        )
        
        return truncate_response(result, len(filtered_vulns))
        
    except ValueError as e:
        return f"Error searching KEV catalog: {str(e)}. Please check your parameters and try again."
    except Exception as e:
        return f"Unexpected error occurred: {str(e)}. Please contact your system administrator if this persists."

@mcp.tool(
    name="analyze_threat_trends",
    annotations={
        "title": "Analyze Vulnerability Threat Trends",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def analyze_threat_trends(params: ThreatAnalysisInput) -> str:
    """Analyze threat trends and patterns in the CISA KEV catalog.
    
    This tool provides strategic threat intelligence by analyzing patterns
    in exploited vulnerabilities. Essential for threat hunting, risk assessment,
    and strategic security planning.
    
    Args:
        params (ThreatAnalysisInput): Analysis parameters containing:
            - analysis_type (str): 'trending', 'critical', 'ransomware', or 'recent'
            - time_period (int): Analysis period in days (7-365, default 30)
            - vendor_focus (Optional[str]): Focus analysis on specific vendor
            - include_predictions (bool): Include threat predictions and recommendations
            - response_format (ResponseFormat): Output format preference
    
    Returns:
        str: Comprehensive threat analysis with trends, patterns, statistics,
             and actionable intelligence for security decision-making.
    """
    try:
        # Fetch latest KEV data
        kev_data = await fetch_cisa_kev_data()
        vulnerabilities = kev_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return "No vulnerability data available for threat analysis."
        
        # Filter by time period
        cutoff_date = datetime.now() - timedelta(days=params.time_period)
        time_filtered = [v for v in vulnerabilities 
                        if datetime.strptime(v.get("dateAdded", "2020-01-01"), "%Y-%m-%d") >= cutoff_date]
        
        # Apply vendor focus if specified
        if params.vendor_focus:
            vendor_lower = params.vendor_focus.lower()
            time_filtered = [v for v in time_filtered 
                           if vendor_lower in v.get("vendorProject", "").lower()]
        
        # Perform analysis based on type
        if params.analysis_type == "trending":
            result = await _analyze_trending_threats(time_filtered, vulnerabilities, params)
        elif params.analysis_type == "critical":
            result = await _analyze_critical_threats(time_filtered, params)
        elif params.analysis_type == "ransomware":
            result = await _analyze_ransomware_threats(time_filtered, params)
        elif params.analysis_type == "recent":
            result = await _analyze_recent_threats(time_filtered, params)
        else:
            return f"Unknown analysis type: {params.analysis_type}"
        
        return truncate_response(result, len(time_filtered))
        
    except ValueError as e:
        return f"Error analyzing threat trends: {str(e)}. Please check your parameters and try again."
    except Exception as e:
        return f"Unexpected error in threat analysis: {str(e)}. Please contact your system administrator."

@mcp.tool(
    name="enrich_cve_intelligence",
    annotations={
        "title": "Enrich CVE with Threat Intelligence",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def enrich_cve_intelligence(params: CVEEnrichmentInput) -> str:
    """Enrich a specific CVE with comprehensive threat intelligence.
    
    This tool provides detailed analysis of a specific CVE, combining CISA KEV data
    with NVD enrichment and threat scoring. Essential for incident response,
    vulnerability assessment, and security research.
    
    Args:
        params (CVEEnrichmentInput): Enrichment parameters containing:
            - cve_id (str): CVE ID in CVE-YYYY-NNNN format
            - include_threat_analysis (bool): Include threat scoring (default True)
            - include_nvd_data (bool): Include NVD enrichment data (default True)
            - response_format (ResponseFormat): Output format preference
    
    Returns:
        str: Comprehensive CVE intelligence report with CISA data, NVD enrichment,
             threat scoring, impact analysis, and remediation recommendations.
    """
    try:
        # Fetch KEV data
        kev_data = await fetch_cisa_kev_data()
        vulnerabilities = kev_data.get("vulnerabilities", [])
        
        # Find the specific CVE
        target_vuln = None
        for vuln in vulnerabilities:
            if vuln.get("cveID", "").upper() == params.cve_id.upper():
                target_vuln = vuln
                break
        
        if not target_vuln:
            return f"CVE {params.cve_id} not found in CISA KEV catalog. This CVE may not be actively exploited or may not exist."
        
        # Enrich with NVD data
        nvd_data = {}
        if params.include_nvd_data:
            nvd_data = await enrich_cve_with_nvd(params.cve_id)
        
        # Add threat analysis
        threat_analysis = {}
        if params.include_threat_analysis:
            threat_analysis = calculate_threat_score(target_vuln, nvd_data)
        
        # Build comprehensive response
        if params.response_format == ResponseFormat.JSON:
            result = {
                "cve_id": params.cve_id,
                "cisa_kev_data": target_vuln,
                "catalog_metadata": {
                    "catalog_version": kev_data.get("catalogVersion"),
                    "last_updated": kev_data.get("dateReleased"),
                    "total_kev_count": kev_data.get("count")
                }
            }
            
            if nvd_data:
                result["nvd_enrichment"] = nvd_data
            if threat_analysis:
                result["threat_analysis"] = threat_analysis
            
            return json.dumps(result, indent=2)
        
        # Markdown format
        output = f"# CVE Intelligence Report: {params.cve_id}\n\n"
        output += f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}\n"
        output += f"**Data Source:** CISA KEV Catalog v{kev_data.get('catalogVersion', 'Unknown')}\n\n"
        
        # CISA KEV Information
        output += f"## 🚨 CISA KEV Information\n\n"
        output += f"**Vulnerability Name:** {target_vuln.get('vulnerabilityName', 'Unknown')}\n"
        output += f"**Vendor/Product:** {target_vuln.get('vendorProject', 'Unknown')} / {target_vuln.get('product', 'Unknown')}\n"
        output += f"**Date Added to KEV:** {target_vuln.get('dateAdded', 'Unknown')}\n"
        output += f"**Remediation Deadline:** {target_vuln.get('dueDate', 'Unknown')}\n"
        output += f"**Known Ransomware Use:** {target_vuln.get('knownRansomwareCampaignUse', 'Unknown')}\n\n"
        
        output += f"**Description:** {target_vuln.get('shortDescription', 'No description available')}\n\n"
        output += f"**Required Action:** {target_vuln.get('requiredAction', 'See vendor guidance')}\n\n"
        
        if target_vuln.get('notes'):
            output += f"**Additional Notes:** {target_vuln.get('notes')}\n\n"
        
        # Threat Analysis
        if threat_analysis:
            output += f"## 🎯 Threat Analysis\n\n"
            output += f"**Threat Score:** {threat_analysis['threat_score']}/100\n"
            output += f"**Threat Level:** {threat_analysis['threat_level'].upper()}\n\n"
            
            if threat_analysis['scoring_factors']:
                output += f"**Risk Factors:**\n"
                for factor in threat_analysis['scoring_factors']:
                    output += f"- {factor}\n"
                output += "\n"
        
        # NVD Enrichment
        if nvd_data:
            output += f"## 📊 NVD Enrichment Data\n\n"
            
            if "descriptions" in nvd_data:
                descriptions = nvd_data["descriptions"]
                if descriptions:
                    output += f"**Technical Description:** {descriptions[0].get('value', 'Not available')}\n\n"
            
            if "metrics" in nvd_data:
                metrics = nvd_data["metrics"]
                if "cvssMetricV31" in metrics or "cvssMetricV3" in metrics:
                    cvss_metrics = metrics.get("cvssMetricV31", metrics.get("cvssMetricV3", []))
                    if cvss_metrics:
                        cvss = cvss_metrics[0]["cvssData"]
                        output += f"**CVSS 3.x Score:** {cvss.get('baseScore', 'N/A')} ({cvss.get('baseSeverity', 'Unknown')})\n"
                        output += f"**Attack Vector:** {cvss.get('attackVector', 'Unknown')}\n"
                        output += f"**Attack Complexity:** {cvss.get('attackComplexity', 'Unknown')}\n"
                        output += f"**Privileges Required:** {cvss.get('privilegesRequired', 'Unknown')}\n"
                        output += f"**User Interaction:** {cvss.get('userInteraction', 'Unknown')}\n\n"
            
            if "weaknesses" in nvd_data and nvd_data["weaknesses"]:
                output += f"**CWE Categories:**\n"
                for weakness in nvd_data["weaknesses"][:3]:  # Show first 3
                    for desc in weakness.get("description", []):
                        output += f"- {desc.get('value', 'Unknown')}\n"
                output += "\n"
        
        # Strategic Recommendations
        output += f"## 💡 Strategic Recommendations\n\n"
        
        if threat_analysis.get('threat_level') in ['critical', 'high']:
            output += f"**⚠️ IMMEDIATE ACTION REQUIRED**\n"
            output += f"- This vulnerability poses significant risk to your environment\n"
            output += f"- Prioritize patching or mitigation within 24-48 hours\n"
            output += f"- Consider emergency change management processes\n\n"
        
        if target_vuln.get('knownRansomwareCampaignUse') == 'Known':
            output += f"**🦠 RANSOMWARE RISK**\n"
            output += f"- This vulnerability is actively used in ransomware campaigns\n"
            output += f"- Implement additional monitoring for this CVE\n"
            output += f"- Review backup and recovery procedures\n\n"
        
        output += f"**General Actions:**\n"
        output += f"- Monitor for exploitation attempts in your environment\n"
        output += f"- Update vulnerability scanners to detect this CVE\n"
        output += f"- Review compliance with BOD 22-01 if applicable\n"
        output += f"- Document remediation efforts for audit purposes\n"
        
        return output
        
    except ValueError as e:
        return f"Error enriching CVE intelligence: {str(e)}. Please verify the CVE ID format (CVE-YYYY-NNNN)."
    except Exception as e:
        return f"Unexpected error in CVE enrichment: {str(e)}. Please contact your system administrator."

@mcp.tool(
    name="get_kev_statistics",
    annotations={
        "title": "Get CISA KEV Catalog Statistics",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def get_kev_statistics() -> str:
    """Get comprehensive statistics and metadata about the CISA KEV catalog.
    
    This tool provides high-level statistics and trends about the KEV catalog,
    useful for executive reporting, compliance tracking, and strategic planning.
    
    Returns:
        str: JSON-formatted statistics including catalog metadata, vendor breakdowns,
             recent trends, ransomware statistics, and key insights.
    """
    try:
        # Fetch latest KEV data
        kev_data = await fetch_cisa_kev_data()
        vulnerabilities = kev_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return json.dumps({"error": "No KEV data available"})
        
        # Calculate statistics
        total_vulns = len(vulnerabilities)
        ransomware_vulns = len([v for v in vulnerabilities if v.get("knownRansomwareCampaignUse") == "Known"])
        
        # Recent additions (last 30 days)
        thirty_days_ago = datetime.now() - timedelta(days=30)
        recent_vulns = [v for v in vulnerabilities 
                       if datetime.strptime(v.get("dateAdded", "2020-01-01"), "%Y-%m-%d") >= thirty_days_ago]
        
        # Vendor breakdown (top 10)
        vendor_counts = {}
        for vuln in vulnerabilities:
            vendor = vuln.get("vendorProject", "Unknown")
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
        
        top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Monthly trend (last 6 months)
        monthly_trends = {}
        six_months_ago = datetime.now() - timedelta(days=180)
        for vuln in vulnerabilities:
            date_added = datetime.strptime(vuln.get("dateAdded", "2020-01-01"), "%Y-%m-%d")
            if date_added >= six_months_ago:
                month_key = date_added.strftime("%Y-%m")
                monthly_trends[month_key] = monthly_trends.get(month_key, 0) + 1
        
        # Build response
        stats = {
            "catalog_metadata": {
                "catalog_version": kev_data.get("catalogVersion"),
                "last_updated": kev_data.get("dateReleased"),
                "total_vulnerabilities": total_vulns
            },
            "security_statistics": {
                "known_ransomware_vulns": ransomware_vulns,
                "ransomware_percentage": round((ransomware_vulns / total_vulns) * 100, 1),
                "recent_additions_30_days": len(recent_vulns),
                "average_monthly_additions": round(len(recent_vulns) / 1, 1) if recent_vulns else 0
            },
            "vendor_breakdown": [
                {"vendor": vendor, "vulnerability_count": count} 
                for vendor, count in top_vendors
            ],
            "monthly_trends_last_6_months": monthly_trends,
            "key_insights": [
                f"Total of {total_vulns} actively exploited vulnerabilities tracked",
                f"{ransomware_vulns} vulnerabilities ({round((ransomware_vulns / total_vulns) * 100, 1)}%) linked to ransomware campaigns",
                f"{len(recent_vulns)} new vulnerabilities added in the last 30 days",
                f"Top affected vendor: {top_vendors[0][0]} with {top_vendors[0][1]} vulnerabilities" if top_vendors else "No vendor data available"
            ],
            "recommendations": [
                "Prioritize patching vulnerabilities with known ransomware usage",
                "Monitor recent additions for emerging threats",
                "Focus remediation efforts on top affected vendors in your environment",
                "Implement automated KEV monitoring for new additions"
            ]
        }
        
        return json.dumps(stats, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Failed to generate KEV statistics: {str(e)}"})

# Helper functions for threat analysis

async def _analyze_trending_threats(time_filtered: List[Dict], all_vulns: List[Dict], params: ThreatAnalysisInput) -> str:
    """Analyze trending threat patterns."""
    # Implementation for trending analysis
    vendor_trends = {}
    for vuln in time_filtered:
        vendor = vuln.get("vendorProject", "Unknown")
        vendor_trends[vendor] = vendor_trends.get(vendor, 0) + 1
    
    trending_vendors = sorted(vendor_trends.items(), key=lambda x: x[1], reverse=True)[:5]
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps({
            "analysis_type": "trending",
            "time_period_days": params.time_period,
            "trending_vendors": [{"vendor": v, "count": c} for v, c in trending_vendors],
            "total_analyzed": len(time_filtered)
        })
    
    output = f"## 📈 Trending Threat Analysis\n\n"
    output += f"**Analysis Period:** Last {params.time_period} days\n"
    output += f"**Vulnerabilities Analyzed:** {len(time_filtered)}\n\n"
    output += f"### Top Trending Vendors:\n"
    for vendor, count in trending_vendors:
        output += f"- **{vendor}:** {count} vulnerabilities\n"
    
    return output

async def _analyze_critical_threats(time_filtered: List[Dict], params: ThreatAnalysisInput) -> str:
    """Analyze critical/high-impact threats."""
    critical_vulns = []
    for vuln in time_filtered:
        threat_data = calculate_threat_score(vuln)
        if threat_data['threat_level'] in ['critical', 'high']:
            vuln['threat_analysis'] = threat_data
            critical_vulns.append(vuln)
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(critical_vulns[:20])
    
    return format_vulnerability_data(critical_vulns, ResponseFormat.MARKDOWN, include_threat_scores=True)

async def _analyze_ransomware_threats(time_filtered: List[Dict], params: ThreatAnalysisInput) -> str:
    """Analyze ransomware-related threats."""
    ransomware_vulns = [v for v in time_filtered if v.get("knownRansomwareCampaignUse") == "Known"]
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(ransomware_vulns)
    
    output = f"## 🦠 Ransomware Threat Analysis\n\n"
    output += f"**Analysis Period:** Last {params.time_period} days\n"
    output += f"**Ransomware-Linked Vulnerabilities:** {len(ransomware_vulns)}\n\n"
    
    return output + format_vulnerability_data(ransomware_vulns, ResponseFormat.MARKDOWN)

async def _analyze_recent_threats(time_filtered: List[Dict], params: ThreatAnalysisInput) -> str:
    """Analyze recently added threats."""
    # Sort by date added (most recent first)
    sorted_vulns = sorted(time_filtered, 
                         key=lambda x: datetime.strptime(x.get("dateAdded", "2020-01-01"), "%Y-%m-%d"), 
                         reverse=True)
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(sorted_vulns[:20])
    
    return format_vulnerability_data(sorted_vulns, ResponseFormat.MARKDOWN)

# Server startup
if __name__ == "__main__":
    # Run with stdio transport (default for MCP)
    mcp.run()
