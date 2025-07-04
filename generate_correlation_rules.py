#!/usr/bin/env python3
"""
Generate correlation rules for UTMStack using Claude Code SDK
This script creates correlation rules for each technology/vendor based on
the documentation and filter fields available.

Default behavior: Skip technologies that already have at least one rule file.
Use --no-skip-existing to process technologies with existing rules.
"""

import os
import sys
import time
import logging
import asyncio
from pathlib import Path
from typing import List, Dict, Tuple
import anyio
import hashlib
import json
from datetime import datetime
from claude_code_sdk import (
    query, 
    ClaudeCodeOptions, 
    AssistantMessage,
    ResultMessage,
    TextBlock,
    CLINotFoundError,
    ProcessError,
    CLIJSONDecodeError
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add a separate handler for file operations logging
file_ops_logger = logging.getLogger(f"{__name__}.file_ops")
file_ops_logger.setLevel(logging.DEBUG)

# Base directory for correlation rules
BASE_DIR = Path(__file__).parent.absolute()

def get_technology_mappings() -> Dict[str, List[Tuple[str, str]]]:
    """
    Returns a mapping of technology folders to their subdirectories and corresponding filters
    """
    return {
        "antivirus": [
            ("bitdefender_gz", "filters_from_github/antivirus/bitdefender_gz.yml"),
            ("sentinel-one", "filters_from_github/antivirus/sentinel-one.yml"),
            ("kaspersky", "filters_from_github/antivirus/kaspersky.yml"),
            ("esmc-eset", "filters_from_github/antivirus/esmc-eset.yml"),
            ("deceptive-bytes", "filters_from_github/deceptivebytes/deceptive-bytes.yml")
        ],
        "aws": [
            ("aws", "filters_from_github/aws/aws.yml")
        ],
        "cisco": [
            ("asa", None),  # No filter file found
            ("cs_switch", None),  # No filter file found
            ("firepower", None),  # No filter file found
            ("meraki", None)  # No filter file found
        ],
        "cloud": [
            ("azure", "filters_from_github/azure/azure-eventhub.yml"),
            ("google", "filters_from_github/google/gcp.yml")
        ],
        "filebeat": [
            ("apache_module", "filters_from_github/filebeat/apache_module.yml"),
            ("auditd_module", "filters_from_github/filebeat/auditd_module.yml"),
            ("elasticsearch_module", "filters_from_github/filebeat/elasticsearch_module.yml"),
            ("haproxy_module", "filters_from_github/filebeat/haproxy_module.yml"),
            ("iis_module", "filters_from_github/filebeat/iis_module.yml"),
            ("kafka_module", "filters_from_github/filebeat/kafka_module.yml"),
            ("kibana_module", "filters_from_github/filebeat/kibana_module.yml"),
            ("logstash_module", "filters_from_github/filebeat/logstash_module.yml"),
            ("mongodb_module", "filters_from_github/filebeat/mongodb_module.yml"),
            ("mysql_module", "filters_from_github/filebeat/mysql_module.yml"),
            ("nats_module", "filters_from_github/filebeat/nats_module.yml"),
            ("nginx_module", "filters_from_github/filebeat/nginx_module.yml"),
            ("osquery_module", "filters_from_github/filebeat/osquery_module.yml"),
            ("postgresql_module", "filters_from_github/filebeat/postgresql_module.yml"),
            ("redis_module", "filters_from_github/filebeat/redis_module.yml"),
            ("system_linux_module", "filters_from_github/filebeat/system_linux_module.yml"),
            ("traefik_module", "filters_from_github/filebeat/traefik_module.yml")
        ],
        "fortinet": [
            ("fortinet", "filters_from_github/fortinet/fortinet.yml"),
            ("fortiweb", "filters_from_github/fortinet/fortiweb.yml")
        ],
        "generic": [
            ("generic", "filters_from_github/generic/generic.yml")
        ],
        "github": [
            ("github", "filters_from_github/github/github.yml")
        ],
        "ibm": [
            ("ibm_aix", "filters_from_github/ibm/ibm_aix.yml"),
            ("ibm_as_400", "filters_from_github/ibm/ibm_as_400.yml")
        ],
        "json": [
            ("json-input", "filters_from_github/json/json-input.yml")
        ],
        "linux": [
            ("debian_family", None),  # No specific filter, will use system_linux_module
            ("rhel_family", None)     # No specific filter, will use system_linux_module
        ],
        "macos": [
            ("macos", "filters_from_github/macos/macos.yml")
        ],
        "mikrotik": [
            ("mikrotik_fw", "filters_from_github/mikrotik/mikrotik-fw.yml")
        ],
        "netflow": [
            ("netflow", "filters_from_github/netflow/netflow.yml")
        ],
        "office365": [
            ("office365", "filters_from_github/office365/o365.yml")
        ],
        "paloalto": [
            ("pa_firewall", "filters_from_github/paloalto/pa_firewall.yml")
        ],
        "pfsense": [
            ("pfsense", "filters_from_github/pfsense/pfsense_fw.yml")
        ],
        "sonicwall": [
            ("sonicwall_firewall", "filters_from_github/sonicwall/sonic_wall.yml")
        ],
        "sophos": [
            ("sophos_central", "filters_from_github/sophos/sophos_central.yml"),
            ("sophos_xg_firewall", "filters_from_github/sophos/sophos_xg_firewall.yml")
        ],
        "syslog": [
            ("cef", None),       # Will use generic syslog
            ("rfc-5424", None),  # Will use generic syslog
            ("rfc-5425", None),  # Will use generic syslog
            ("rfc-6587", None)   # Will use generic syslog
        ],
        "vmware": [
            ("vmware-esxi", "filters_from_github/vmware/vmware-esxi.yml")
        ],
        "windows": [
            ("windows", "filters_from_github/windows/windows-events.yml")
        ],
        "hids": [
            ("hids", None)  # No specific filter file
        ],
        "nids": [
            ("nids", None)  # No specific filter file
        ]
    }

def check_existing_rules(tech_folder: Path, rules: List[str]) -> int:
    """
    Check how many rules from the batch already exist in the technology folder
    """
    if not tech_folder.exists():
        return 0
    
    existing_count = 0
    existing_files = list(tech_folder.glob("*.yml"))
    
    # Create a list of rule names from existing files
    existing_rule_names = []
    for file in existing_files:
        try:
            with open(file, 'r') as f:
                content = f.read()
                # Try to extract rule name from the file
                for line in content.split('\n'):
                    if line.strip().startswith('name:'):
                        rule_name = line.split('name:', 1)[1].strip()
                        existing_rule_names.append(rule_name.lower())
                        break
        except:
            continue
    
    # Check each rule in the batch
    for rule in rules:
        rule_lower = rule.lower()
        # Check if this rule name already exists (fuzzy match)
        for existing_name in existing_rule_names:
            # Check for exact match or significant similarity
            if (rule_lower == existing_name or 
                rule_lower in existing_name or 
                existing_name in rule_lower or
                # Check if key words match
                all(word in existing_name for word in rule_lower.split()[:3])):
                existing_count += 1
                logger.debug(f"Rule '{rule}' appears to already exist as '{existing_name}'")
                break
    
    return existing_count

def get_rules_for_technology(tech_name: str) -> List[str]:
    """
    Extract the relevant rules from ruleslist.md for a specific technology
    """
    rules_file = BASE_DIR / "ruleslist.md"
    if not rules_file.exists():
        logger.error(f"ruleslist.md not found at {rules_file}")
        return []
    
    with open(rules_file, 'r') as f:
        content = f.read()
    
    # Map technology names to their sections in ruleslist.md
    section_mappings = {
        "bitdefender_gz": "BitDefender",
        "sentinel-one": "Sentinel One",
        "kaspersky": "Kaspersky",
        "esmc-eset": "ESET",
        "deceptive-bytes": "Deceptive Bytes",
        "aws": "AWS",
        "asa": "Cisco ASA",
        "cs_switch": "Cisco Switches",
        "firepower": "Cisco Firepower",
        "meraki": "Cisco Meraki",
        "azure": "Azure",
        "google": "Google Cloud Platform",
        "apache_module": "Apache Module",
        "auditd_module": "Auditd Module",
        "elasticsearch_module": "Elasticsearch Module",
        "haproxy_module": "HAProxy Module",
        "iis_module": "IIS Module",
        "kafka_module": "Kafka Module",
        "kibana_module": "Kibana Module",
        "logstash_module": "Logstash Module",
        "mongodb_module": "MongoDB Module",
        "mysql_module": "MySQL Module",
        "nats_module": "NATS Module",
        "nginx_module": "Nginx Module",
        "osquery_module": "OSQuery Module",
        "postgresql_module": "PostgreSQL Module",
        "redis_module": "Redis Module",
        "system_linux_module": "System Linux Module",
        "traefik_module": "Traefik Module",
        "fortinet": "Fortinet FortiGate",
        "fortiweb": "FortiWeb",
        "generic": "GENERIC",
        "github": "GITHUB",
        "ibm_aix": "IBM AIX",
        "ibm_as_400": "IBM AS/400",
        "json-input": "JSON INPUT",
        "debian_family": "Debian Family",
        "rhel_family": "RHEL Family",
        "macos": "MACOS",
        "mikrotik_fw": "MIKROTIK",
        "netflow": "NETFLOW",
        "office365": "OFFICE365",
        "pa_firewall": "PALO ALTO",
        "pfsense": "PFSENSE",
        "sonicwall_firewall": "SONICWALL",
        "sophos_central": "Sophos Central",
        "sophos_xg_firewall": "Sophos XG Firewall",
        "cef": "CEF",
        "rfc-5424": "RFC-5424",
        "rfc-5425": "RFC-5425",
        "rfc-6587": "RFC-6587",
        "vmware-esxi": "VMware ESXi",
        "windows": "WINDOWS",
        "hids": "HIDS",
        "nids": "NIDS"
    }
    
    section_name = section_mappings.get(tech_name, tech_name.upper())
    
    # Find the section and extract rules
    rules = []
    in_section = False
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        if section_name in line and (line.startswith('###') or line.startswith('####')):
            in_section = True
            continue
        elif in_section and line.startswith('###') and i > 0:
            # End of current section
            break
        elif in_section and line.startswith('- '):
            # This is a rule
            rules.append(line[2:].strip())
    
    return rules

async def verify_files_created(tech_folder: Path, expected_rules: List[str], start_id: int) -> int:
    """
    Verify that files were actually created for the expected rules
    Returns the number of files successfully created
    """
    if not tech_folder.exists():
        file_ops_logger.error(f"Technology folder does not exist: {tech_folder}")
        return 0
    
    # Get current files in the directory
    current_files = list(tech_folder.glob("*.yml"))
    file_ops_logger.info(f"Checking {tech_folder} - found {len(current_files)} total YAML files")
    
    # Track files created
    created_count = 0
    created_files = []
    
    # Check each expected rule
    for idx, rule in enumerate(expected_rules):
        rule_id = 1000 + start_id + idx + 1
        rule_found = False
        
        # Look for files that might contain this rule
        for file_path in current_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                # Check if this file contains the expected rule ID or name
                if (f"id: {rule_id}" in content or 
                    rule.lower() in content.lower() or
                    # Check for variations of the rule name
                    rule.replace(" ", "_").lower() in file_path.name.lower() or
                    rule.replace(" ", "-").lower() in file_path.name.lower()):
                    
                    rule_found = True
                    created_files.append(file_path.name)
                    file_ops_logger.debug(f"Found rule '{rule}' (ID: {rule_id}) in file: {file_path.name}")
                    
                    # Verify file is not empty and has valid YAML structure
                    if len(content.strip()) < 50:
                        file_ops_logger.warning(f"File {file_path.name} seems too small ({len(content)} bytes)")
                    
                    break
                    
            except Exception as e:
                file_ops_logger.error(f"Error reading file {file_path}: {e}")
        
        if rule_found:
            created_count += 1
        else:
            file_ops_logger.warning(f"Could not find file for rule: '{rule}' (expected ID: {rule_id})")
    
    # Log summary
    if created_count > 0:
        file_ops_logger.info(f"Verified {created_count}/{len(expected_rules)} rules were created")
        file_ops_logger.info(f"Created files: {', '.join(created_files[:5])}{'...' if len(created_files) > 5 else ''}")
    else:
        file_ops_logger.error(f"NO FILES were created for any of the {len(expected_rules)} expected rules!")
        
        # Additional debugging
        file_ops_logger.debug(f"Expected rules: {expected_rules[:3]}..." if len(expected_rules) > 3 else expected_rules)
        file_ops_logger.debug(f"Files in directory: {[f.name for f in current_files[:5]]}{'...' if len(current_files) > 5 else ''}")
    
    return created_count

def save_execution_state(state_file: Path, tech_name: str, status: str, files_created: int = 0):
    """
    Save the execution state to track progress and detect issues
    """
    state = {}
    if state_file.exists():
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
        except:
            state = {}
    
    if tech_name not in state:
        state[tech_name] = []
    
    state[tech_name].append({
        "timestamp": datetime.now().isoformat(),
        "status": status,
        "files_created": files_created
    })
    
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=2)

def create_claude_prompt(tech_name: str, tech_folder: str, filter_path: str, rules: List[str], batch_num: int = 1, total_batches: int = 1) -> str:
    """
    Create a detailed prompt for Claude to generate correlation rules
    """
    batch_info = f" (Batch {batch_num} of {total_batches})" if total_batches > 1 else ""
    
    prompt = f"""You are tasked with creating correlation rules for {tech_name} in the UTMStack system{batch_info}.

IMPORTANT: Follow these instructions EXACTLY:

1. Create correlation rules based on the list provided below
2. Each rule should follow the YAML structure defined in rulesdoc.md
3. If a filter file is provided, examine it first to understand available fields
4. If you need to find specific log field names or event types for {tech_name}, use WebSearch to look up the vendor's documentation
   - Search for terms like "{tech_name} log fields", "{tech_name} event types", "{tech_name} syslog format"
   - Look for official documentation URLs from the vendor
5. IMPORTANT: You MUST use the Write tool to save each rule as a separate YAML file in the folder: {tech_folder}
6. Name each file descriptively based on the rule, e.g., "brute_force_detection.yml", "malware_outbreak.yml"
   - DO NOT just show the YAML content, you MUST save it to a file using the Write tool
   - After creating each file, confirm that it was saved successfully
7. Each rule file should contain a single rule in the correct YAML format
8. Use appropriate CEL expressions in the 'where' field based on actual vendor field names
9. Set realistic impact scores (confidentiality, integrity, availability) from 0-5
10. Include relevant references where applicable (vendor docs and MITRE ATT&CK)
11. Use the "safe" function for fields that might not exist
12. Fields not from filters should start with "log."
13. Start rule IDs from {1000 + (batch_num - 1) * len(rules) + 1}

Filter file location: {filter_path if filter_path else 'No specific filter file, use generic log fields'}

{'If a filter file is provided, FIRST read and analyze it to understand:' if filter_path else ''}
{'- Available field names after parsing (look at rename operations)' if filter_path else ''}
{'- Data types being processed' if filter_path else ''}
{'- Field transformations and mappings' if filter_path else ''}
{'Then use these actual field names in your rules.' if filter_path else ''}

Rules to implement for {tech_name}:
{chr(10).join(f'- {rule}' for rule in rules)}

Example rule structure:
```yaml
- id: {1000 + (batch_num - 1) * len(rules) + 1}
  dataTypes:
    - {tech_name}
  name: Example Rule Name
  impact:
    confidentiality: 3
    integrity: 2
    availability: 4
  category: Security Category
  technique: Attack Technique
  adversary: origin
  references:
    - https://example.com/reference
  description: Detailed description of what this rule detects
  where: safe(origin.ip, "") != "" && safe(log.eventType, "") == "suspicious"
  afterEvents:
    - indexPattern: v11-log-*
      with:
        - field: origin.ip.keyword
          operator: filter_term
          value: '{{{{origin.ip}}}}'
      within: now-1h
      count: 5
  deduplicateBy:
    - origin.ip
```

Please create the correlation rules now. Start with the first rule and save it to the appropriate file.

REMEMBER: You must use the Write tool to actually save each rule to a file. Do not just display the YAML content."""
    
    return prompt

async def run_claude_code(prompt: str, working_dir: str) -> bool:
    """
    Run Claude Code SDK with the given prompt
    """
    try:
        logger.info(f"Running Claude Code SDK for directory: {working_dir}")
        
        # Configure options for Claude Code
        options = ClaudeCodeOptions(
            max_turns=15,  # Increased to ensure all files can be created
            cwd=working_dir,
            allowed_tools=["Read", "Write", "MultiEdit", "Grep", "Glob", "WebSearch"],
            permission_mode="acceptEdits"  # Automatically accept edits
        )
        
        messages = []
        result = None
        files_mentioned = []
        
        async for message in query(prompt=prompt, options=options):
            messages.append(message)
            
            # Log assistant messages and extract file mentions
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        text = block.text
                        logger.debug(f"Claude: {text[:100]}...")
                        
                        # Extract file mentions from Claude's responses
                        import re
                        file_patterns = [
                            r"(?:Creating|Writing|Saving|Generated|Wrote).*?([\w_-]+\.yml)",
                            r"file[:\s]+([\w_-]+\.yml)",
                            r"([\w_-]+\.yml).*?(?:created|saved|written|wrote)",
                            r"Write tool.*?([\w_-]+\.yml)"
                        ]
                        
                        for pattern in file_patterns:
                            matches = re.findall(pattern, text, re.IGNORECASE)
                            files_mentioned.extend(matches)
                        
                        # Log Write tool usage
                        if "Write tool" in text or "Writing" in text:
                            file_ops_logger.debug(f"Claude mentioned using Write tool: {text[:200]}...")
            
            # Capture the final result
            if isinstance(message, ResultMessage):
                result = message
                # Check if cost_cents attribute exists
                if hasattr(result, 'cost_cents'):
                    logger.debug(f"Task completed. Cost: {result.cost_cents/100:.2f} USD")
                else:
                    logger.debug("Task completed successfully")
        
        if files_mentioned:
            logger.info(f"Claude mentioned creating these files: {', '.join(set(files_mentioned))}")
        
        logger.info("Claude Code SDK execution completed successfully")
        return True
            
    except CLINotFoundError:
        logger.error("Claude Code CLI not found. Please install: npm install -g @anthropic-ai/claude-code")
        return False
    except ProcessError as e:
        logger.error(f"Claude Code process failed with exit code {e.exit_code}: {e.stderr}")
        return False
    except CLIJSONDecodeError as e:
        logger.error(f"Failed to decode Claude Code response: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error running Claude Code SDK: {str(e)}")
        return False

async def main():
    """
    Main function to orchestrate rule generation
    """
    import argparse
    
    # Create state file for tracking execution
    state_file = BASE_DIR / "generation_state.json"
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Generate UTMStack correlation rules')
    parser.add_argument('--force', '-f', action='store_true', help='Force regeneration of existing rules')
    parser.add_argument('--technology', '-t', type=str, help='Generate rules for specific technology only (e.g., antivirus/bitdefender_gz)')
    parser.add_argument('--no-skip-existing', action='store_true', help='Process technologies even if they have existing rules')
    parser.add_argument('--skip-existing', '-s', action='store_true', default=True, help='Skip existing rules within a technology (default: True)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--retry-failed', action='store_true', help='Retry batches that failed to create files')
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        file_ops_logger.setLevel(logging.DEBUG)
    
    logger.info("Starting correlation rule generation")
    
    # Log the mode being used
    if args.force:
        logger.info("Mode: FORCE - Will regenerate all rules even if they exist")
    elif args.no_skip_existing:
        logger.info("Mode: PROCESS ALL - Will process technologies even if they have existing rules")
    else:
        logger.info("Mode: SKIP EXISTING (default) - Will skip technologies that already have rule files")
    
    # Get technology mappings
    tech_mappings = get_technology_mappings()
    
    # Filter by specific technology if requested
    if args.technology:
        tech_parts = args.technology.split('/')
        if len(tech_parts) == 2:
            category, tech = tech_parts
            if category in tech_mappings:
                # Filter to only the specified technology
                filtered = [(t, p) for t, p in tech_mappings[category] if t == tech]
                if filtered:
                    tech_mappings = {category: filtered}
                    logger.info(f"Filtering to technology: {args.technology}")
                else:
                    logger.error(f"Technology '{tech}' not found in category '{category}'")
                    return
            else:
                logger.error(f"Category '{category}' not found")
                return
        else:
            logger.error("Technology must be in format: category/technology (e.g., antivirus/bitdefender_gz)")
            return
    
    total_technologies = sum(len(subdirs) for subdirs in tech_mappings.values())
    processed = 0
    failed = []
    total_skipped = 0
    total_created = 0
    
    # Process each technology (limiting to first one for testing)
    test_mode = False  # Set to False to process all technologies
    
    for tech_category, subdirs in tech_mappings.items():
        for tech_name, filter_path in subdirs:
            processed += 1
            logger.info(f"Processing {processed}/{total_technologies}: {tech_category}/{tech_name}")
            
            # Get rules for this technology
            rules = get_rules_for_technology(tech_name)
            if not rules:
                logger.warning(f"No rules found for {tech_name}, skipping")
                continue
            
            logger.info(f"Found {len(rules)} rules for {tech_name}")
            
            # Create target folder path
            tech_folder = BASE_DIR / tech_category / tech_name
            
            # Default behavior: Skip technology if any rule files already exist (unless --no-skip-existing is used)
            if not args.no_skip_existing and tech_folder.exists():
                existing_files = list(tech_folder.glob("*.yml"))
                if existing_files:
                    logger.info(f"Skipping {tech_category}/{tech_name} - found {len(existing_files)} existing rule files (use --no-skip-existing to process anyway)")
                    total_skipped += len(rules)  # Count all rules as skipped
                    continue
            
            # Ensure the folder exists
            tech_folder.mkdir(parents=True, exist_ok=True)
            
            # Full filter path if it exists
            full_filter_path = BASE_DIR / filter_path if filter_path else None
            
            # Batch processing for technologies with many rules
            batch_size = 5  # Reduced from 10 to 5 for better processing
            total_batches = (len(rules) + batch_size - 1) // batch_size  # Ceiling division
            
            tech_success = True
            for batch_num in range(1, total_batches + 1):
                start_idx = (batch_num - 1) * batch_size
                end_idx = min(batch_num * batch_size, len(rules))
                batch_rules = rules[start_idx:end_idx]
                
                # Check if rules in this batch already exist (unless force is set)
                if not args.force and args.skip_existing:
                    existing_count = check_existing_rules(tech_folder, batch_rules)
                    
                    if existing_count == len(batch_rules):
                        logger.info(f"Skipping batch {batch_num}/{total_batches} for {tech_name} - all {existing_count} rules already exist")
                        total_skipped += existing_count
                        continue
                    elif existing_count > 0:
                        logger.info(f"Batch {batch_num}/{total_batches} for {tech_name} - {existing_count}/{len(batch_rules)} rules already exist")
                        total_skipped += existing_count
                
                if total_batches > 1:
                    logger.info(f"Processing batch {batch_num}/{total_batches} for {tech_name} ({len(batch_rules)} rules)")
                
                # Pre-check: Count existing files before processing
                pre_check_files = list(tech_folder.glob("*.yml"))
                logger.info(f"Pre-check: Found {len(pre_check_files)} existing YAML files in {tech_folder.name}")
                
                # Create prompt for this batch
                prompt = create_claude_prompt(
                    tech_name=tech_name,
                    tech_folder=str(tech_folder),
                    filter_path=str(full_filter_path) if full_filter_path else None,
                    rules=batch_rules,
                    batch_num=batch_num,
                    total_batches=total_batches
                )
                
                # Run Claude Code
                success = await run_claude_code(prompt, str(BASE_DIR))
                
                if not success:
                    tech_success = False
                    logger.error(f"Failed to generate rules for {tech_name} (batch {batch_num})")
                    break  # Stop processing further batches for this tech
                else:
                    # Post-check: Count files after processing
                    post_check_files = list(tech_folder.glob("*.yml"))
                    new_files_count = len(post_check_files) - len(pre_check_files)
                    logger.info(f"Post-check: Found {len(post_check_files)} YAML files ({new_files_count} new files)")
                    
                    # Verify files were actually created
                    files_created = await verify_files_created(tech_folder, batch_rules, start_idx)
                    
                    if files_created > 0:
                        logger.info(f"Successfully generated {files_created} rule files for {tech_name} (batch {batch_num})")
                        total_created += files_created
                        save_execution_state(state_file, f"{tech_category}/{tech_name}", "success", files_created)
                    else:
                        logger.error(f"WARNING: Claude reported success but NO FILES were created for {tech_name} (batch {batch_num})")
                        save_execution_state(state_file, f"{tech_category}/{tech_name}", "no_files_created", 0)
                        
                        # Retry once if no files were created
                        if args.retry_failed:
                            logger.info(f"Retrying batch {batch_num} for {tech_name}...")
                            await asyncio.sleep(3)
                            
                            # Try again with more explicit instructions
                            retry_prompt = prompt + "\n\nIMPORTANT: Make sure to actually create and write the YAML files. Use the Write tool to save each rule as a separate file."
                            retry_success = await run_claude_code(retry_prompt, str(BASE_DIR))
                            
                            if retry_success:
                                files_created = await verify_files_created(tech_folder, batch_rules, start_idx)
                                if files_created > 0:
                                    logger.info(f"Retry successful! Generated {files_created} rule files for {tech_name} (batch {batch_num})")
                                    total_created += files_created
                                    save_execution_state(state_file, f"{tech_category}/{tech_name}", "retry_success", files_created)
                                else:
                                    logger.error(f"Retry failed - still no files created for {tech_name} (batch {batch_num})")
                                    tech_success = False
                                    save_execution_state(state_file, f"{tech_category}/{tech_name}", "retry_failed", 0)
                            else:
                                tech_success = False
                
                # Delay between batches
                if batch_num < total_batches:
                    await asyncio.sleep(2)
            
            if not tech_success:
                failed.append(f"{tech_category}/{tech_name}")
                logger.error(f"Failed to generate all rules for {tech_name}")
            else:
                logger.info(f"Successfully generated all rules for {tech_name}")
            
            # Add a small delay between calls to avoid rate limiting
            await asyncio.sleep(2)
            
            # Exit after first technology in test mode
            if test_mode:
                logger.info("Test mode: Exiting after first technology")
                break
        if test_mode:
            break
    
    # Summary
    logger.info(f"\nGeneration complete!")
    logger.info(f"Total technologies processed: {processed}")
    logger.info(f"Rules created: {total_created}")
    logger.info(f"Rules skipped (already exist): {total_skipped}")
    logger.info(f"Failed technologies: {len(failed)}")
    if failed:
        logger.error(f"Failed technologies: {', '.join(failed)}")
    
    # Log state file location
    logger.info(f"\nExecution state saved to: {state_file}")
    logger.info("Review this file to see detailed execution history and any issues.")
    
    if args.force:
        logger.info("\nNote: Force mode was enabled - existing rules were overwritten")
    elif args.no_skip_existing:
        logger.info("\nNote: Technologies with existing files were processed (--no-skip-existing was used)")
    else:
        logger.info("\nNote: Technologies with existing rule files were skipped (default behavior)")
        logger.info("      Use --no-skip-existing to process technologies that already have rules")

if __name__ == "__main__":
    # Use anyio for better async compatibility
    anyio.run(main)