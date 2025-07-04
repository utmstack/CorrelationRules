#!/usr/bin/env python3
"""
Import correlation rules from UTMStack repository using Claude Code SDK

This script:
1. Clones/updates the UTMStack correlation rules repository
2. Analyzes each rule file from the repository
3. Checks if a similar rule already exists in the local project
4. If no duplicate exists, converts and imports the rule following rulesdoc.md
5. Uses standardized field names from filters_from_github/
6. Processes rules one by one to ensure accuracy
"""

import os
import sys
import time
import logging
import asyncio
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import anyio
import yaml
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

# Base directory for the project
BASE_DIR = Path(__file__).parent.absolute()

def clone_or_update_repo(repo_url: str, local_path: Path) -> bool:
    """
    Clone or update the UTMStack correlation rules repository
    """
    try:
        if local_path.exists():
            # Update existing repo
            logger.info(f"Updating repository at {local_path}")
            os.system(f"cd {local_path} && git pull")
        else:
            # Clone repo
            logger.info(f"Cloning repository from {repo_url}")
            os.system(f"git clone {repo_url} {local_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to clone/update repository: {str(e)}")
        return False

def explore_utmstack_repo(repo_path: Path, output_file: Path) -> Dict[str, List[Path]]:
    """
    Explore UTMStack repository structure and organize rules by technology
    """
    tech_rules = {}
    structure_lines = []
    
    # Common rule file patterns for UTMStack
    rule_extensions = {'.yml', '.yaml'}
    skip_dirs = {'.git', '__pycache__', 'docs', 'scripts', 'tests'}
    skip_files = {'README.md', '.gitignore', 'LICENSE'}
    
    structure_lines.append(f"UTMStack Repository Structure: {repo_path}")
    structure_lines.append("=" * 80)
    structure_lines.append("")
    
    # Look for technology folders in the repo
    for tech_dir in repo_path.iterdir():
        if tech_dir.is_dir() and tech_dir.name not in skip_dirs:
            tech_name = tech_dir.name
            tech_rules[tech_name] = []
            structure_lines.append(f"{tech_name}/")
            
            # Find rule files in technology directory
            for rule_file in tech_dir.rglob("*.yml"):
                if rule_file.name not in skip_files:
                    tech_rules[tech_name].append(rule_file)
                    structure_lines.append(f"  - {rule_file.relative_to(tech_dir)}")
    
    # Write structure to file
    total_rules = sum(len(rules) for rules in tech_rules.values())
    with open(output_file, 'w') as f:
        f.write('\n'.join(structure_lines))
        f.write(f"\n\nTotal technologies: {len(tech_rules)}\n")
        f.write(f"Total rule files: {total_rules}\n\n")
        
        for tech, rules in tech_rules.items():
            f.write(f"\n{tech}: {len(rules)} rules\n")
    
    logger.info(f"Repository structure saved to: {output_file}")
    logger.info(f"Found {len(tech_rules)} technologies with {total_rules} total rules")
    
    return tech_rules

def detect_rule_format(file_path: Path) -> str:
    """
    Try to detect the format of a rule file
    """
    content = file_path.read_text(encoding='utf-8', errors='ignore')
    
    # Check for various rule formats
    if file_path.suffix in ['.yml', '.yaml']:
        if 'detection:' in content or 'logsource:' in content:
            return "sigma"
        elif 'rule:' in content or 'alert:' in content:
            return "suricata"
        else:
            return "yaml_generic"
    elif file_path.suffix == '.json':
        return "json_generic"
    elif 'alert' in content and 'msg:' in content:
        return "snort"
    elif '<rule' in content.lower() and '</rule>' in content.lower():
        return "xml_wazuh"
    else:
        return "unknown"

def get_technology_from_path(file_path: Path) -> Tuple[str, str]:
    """
    Try to determine technology from file path and content
    """
    parts = file_path.parts
    file_name = file_path.stem.lower()
    
    # Read first few lines to look for technology hints
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content_preview = f.read(1000).lower()
    except:
        content_preview = ""
    
    # Comprehensive technology mapping
    tech_mappings = {
        # Antivirus
        ('bitdefender', 'antivirus', 'bitdefender_gz'),
        ('kaspersky', 'antivirus', 'kaspersky'),
        ('eset', 'antivirus', 'esmc-eset'),
        ('sentinel', 'antivirus', 'sentinel-one'),
        ('crowdstrike', 'antivirus', 'crowdstrike'),
        ('defender', 'antivirus', 'windows-defender'),
        
        # Cloud
        ('aws', 'aws', 'aws'),
        ('cloudtrail', 'aws', 'aws'),
        ('azure', 'cloud', 'azure'),
        ('gcp', 'cloud', 'google'),
        ('google cloud', 'cloud', 'google'),
        
        # Network devices
        ('cisco', 'cisco', 'asa'),
        ('asa', 'cisco', 'asa'),
        ('firepower', 'cisco', 'firepower'),
        ('meraki', 'cisco', 'meraki'),
        ('fortinet', 'fortinet', 'fortinet'),
        ('fortigate', 'fortinet', 'fortinet'),
        ('paloalto', 'paloalto', 'pa_firewall'),
        ('pan-os', 'paloalto', 'pa_firewall'),
        
        # Operating systems
        ('windows', 'windows', 'windows'),
        ('event id', 'windows', 'windows'),
        ('linux', 'linux', 'debian_family'),
        ('ubuntu', 'linux', 'debian_family'),
        ('centos', 'linux', 'rhel_family'),
        ('redhat', 'linux', 'rhel_family'),
        ('macos', 'macos', 'macos'),
        
        # Security tools
        ('suricata', 'nids', 'nids'),
        ('snort', 'nids', 'nids'),
        ('wazuh', 'hids', 'hids'),
        ('ossec', 'hids', 'hids'),
        
        # Applications
        ('apache', 'filebeat', 'apache_module'),
        ('nginx', 'filebeat', 'nginx_module'),
        ('mysql', 'filebeat', 'mysql_module'),
        ('postgresql', 'filebeat', 'postgresql_module'),
        ('elasticsearch', 'filebeat', 'elasticsearch_module'),
    }
    
    # Check file path and content for technology indicators
    combined_text = ' '.join(parts).lower() + ' ' + file_name + ' ' + content_preview
    
    for indicator, category, tech_name in tech_mappings:
        if indicator in combined_text:
            return category, tech_name
    
    # Fallback to path-based detection
    for i, part in enumerate(parts):
        part_lower = part.lower()
        if part_lower in ['antivirus', 'firewall', 'ids', 'siem', 'windows', 'linux', 'network']:
            if i + 1 < len(parts):
                return part_lower, parts[i + 1]
            else:
                return part_lower, "generic"
    
    return "generic", "generic"

def get_existing_rules_for_technology(tech_category: str, tech_name: str) -> List[Path]:
    """
    Get all existing rules for a technology in the local project
    """
    local_tech_path = BASE_DIR / tech_category / tech_name
    if local_tech_path.exists():
        return list(local_tech_path.glob("*.yml"))
    return []

def create_analysis_prompt(rule_file: Path, tech_name: str, existing_rules: List[Path]) -> str:
    """
    Create a detailed prompt for Claude to analyze and potentially import a rule
    """
    prompt = f"""You are tasked with analyzing a correlation rule from the UTMStack repository and determining if it should be imported.

IMPORTANT: Follow these analysis steps EXACTLY:

1. Read the rule file from the UTMStack repository: {rule_file}

2. Analyze the rule to understand:
   - What threat/attack it detects
   - The core detection logic
   - Key fields and conditions used

3. Check if a similar rule already exists locally by:
   - Reading each existing rule file for this technology
   - Comparing the detection logic and purpose
   - Looking for rules that detect the same threat/pattern
   
   Existing rules for {tech_name}:
   {chr(10).join(f'   - {r.name}' for r in existing_rules) if existing_rules else '   - No existing rules'}

4. DECISION POINT:
   - If a rule with the same functionality exists: STOP and report "DUPLICATE: [existing_rule_name]"
   - If no similar rule exists: PROCEED to convert the rule

5. If converting (no duplicate exists), follow these standards:
   - FIRST: Check if a filter file exists for the detected technology in filters_from_github/
   - If a filter exists, READ IT to understand:
     * The dataTypes value to use (e.g., "antivirus-bitdefender-gz")
     * Field names after parsing (check rename operations)
     * Available fields after all transformations
   - Use standardized field names based on filter output:
     * Source IP: origin.ip (if renamed in filter)
     * Destination IP: target.ip  
     * Source Port: origin.port
     * Destination Port: target.port
     * Username: origin.user or target.user
     * Hostname: origin.hostname or target.hostname
     * Process: origin.process or target.process
     * File Path: origin.path or target.path
   - For fields NOT renamed by filters, prefix with "log." (e.g., log.eventType, log.severity)
   - Always use the "safe" function for fields that might not exist
   - Match the exact dataTypes value from the filter file

6. Conversion Guidelines:
   - Generate appropriate rule IDs starting from 3000 + (incremental number)
   - Set realistic impact scores (0-5) based on the threat
   - Add proper MITRE ATT&CK references where applicable
   - Create clear descriptions explaining what the rule detects
   - Include investigation steps in the description
   - Use proper CEL expressions for the 'where' clause
   - Convert time windows appropriately (e.g., "5m" → "now-5m")

7. Technology Mapping:
   Map the repository technology name to our local structure:
   - Repository: {tech_name}
   - Determine appropriate local category (antivirus, aws, cisco, etc.)
   - Save in: <category>/<technology>/<descriptive_name>.yml

Repository rule file: {rule_file}
Technology: {tech_name}

Example UTMStack rule format:
```yaml
- id: 2001
  dataTypes:
    - technology-name
  name: Descriptive Rule Name
  impact:
    confidentiality: 3
    integrity: 2
    availability: 1
  category: Attack Category
  technique: MITRE Technique
  adversary: origin
  references:
    - https://attack.mitre.org/techniques/TXXXX/
  description: |
    Clear description of what this rule detects.
    
    Next Steps:
    - Investigation step 1
    - Investigation step 2
    - Remediation recommendations
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

Please proceed with the conversion now."""
    
    return prompt

async def analyze_and_import_rule(rule_file: Path, tech_name: str, working_dir: str) -> Tuple[str, Optional[str]]:
    """
    Analyze a single rule and import if not duplicate
    Returns: (status, created_file_path)
    status can be: 'imported', 'duplicate', 'error'
    """
    try:
        logger.info(f"Analyzing rule: {rule_file.name} from {tech_name}")
        
        # Determine local technology mapping
        tech_category, local_tech_name = map_repo_tech_to_local(tech_name)
        
        # Get existing rules for this technology
        existing_rules = get_existing_rules_for_technology(tech_category, local_tech_name)
        
        # Create analysis prompt
        prompt = create_analysis_prompt(rule_file, tech_name, existing_rules)
        
        # Configure options for Claude Code
        options = ClaudeCodeOptions(
            max_turns=15,  # Allow more turns for complex conversions
            cwd=working_dir,
            allowed_tools=["Read", "Write", "MultiEdit", "Grep", "Glob", "WebSearch"],
            permission_mode="acceptEdits"
        )
        
        messages = []
        result = None
        status = 'error'
        created_file = None
        
        async for message in query(prompt=prompt, options=options):
            messages.append(message)
            
            # Log assistant messages
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        text = block.text
                        # Check for duplicate detection
                        if "DUPLICATE:" in text:
                            status = 'duplicate'
                            logger.info(f"Rule is duplicate: {text}")
                        # Check for file creation
                        elif "created" in text.lower() or "saved" in text.lower():
                            status = 'imported'
                            created_file = text
                        logger.debug(f"Claude: {text[:100]}...")
            
            # Capture the final result
            if isinstance(message, ResultMessage):
                result = message
                if hasattr(result, 'cost_cents'):
                    logger.debug(f"Analysis completed. Cost: {result.cost_cents/100:.2f} USD")
                else:
                    logger.debug("Analysis completed successfully")
        
        return status, created_file
            
    except CLINotFoundError:
        logger.error("Claude Code CLI not found. Please install: npm install -g @anthropic-ai/claude-code")
        return 'error', None
    except ProcessError as e:
        logger.error(f"Claude Code process failed with exit code {e.exit_code}: {e.stderr}")
        return 'error', None
    except CLIJSONDecodeError as e:
        logger.error(f"Failed to decode Claude Code response: {str(e)}")
        return 'error', None
    except Exception as e:
        logger.error(f"Unexpected error analyzing rule: {str(e)}")
        return 'error', None

def map_repo_tech_to_local(repo_tech: str) -> Tuple[str, str]:
    """
    Map repository technology name to local category and technology
    """
    # Mapping from repo names to local structure
    tech_mappings = {
        # Direct mappings
        'aws': ('aws', 'aws'),
        'azure': ('cloud', 'azure'),
        'gcp': ('cloud', 'google'),
        'windows': ('windows', 'windows'),
        'linux': ('linux', 'debian_family'),
        'macos': ('macos', 'macos'),
        'office365': ('office365', 'office365'),
        'github': ('github', 'github'),
        
        # Network devices
        'cisco': ('cisco', 'asa'),
        'cisco-asa': ('cisco', 'asa'),
        'cisco-firepower': ('cisco', 'firepower'),
        'fortinet': ('fortinet', 'fortinet'),
        'paloalto': ('paloalto', 'pa_firewall'),
        'sonicwall': ('sonicwall', 'sonicwall_firewall'),
        'pfsense': ('pfsense', 'pfsense'),
        
        # Antivirus
        'bitdefender': ('antivirus', 'bitdefender_gz'),
        'kaspersky': ('antivirus', 'kaspersky'),
        'eset': ('antivirus', 'esmc-eset'),
        'sentinelone': ('antivirus', 'sentinel-one'),
        
        # Security tools
        'wazuh': ('hids', 'hids'),
        'suricata': ('nids', 'nids'),
        'snort': ('nids', 'nids'),
    }
    
    # Try exact match first
    if repo_tech.lower() in tech_mappings:
        return tech_mappings[repo_tech.lower()]
    
    # Try partial matches
    for key, value in tech_mappings.items():
        if key in repo_tech.lower() or repo_tech.lower() in key:
            return value
    
    # Default to generic
    return ('generic', 'generic')

async def main():
    """
    Main function to orchestrate rule import from UTMStack repository
    """
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Import rules from UTMStack correlation repository')
    parser.add_argument('--repo-url', '-r', type=str, 
                       default='https://github.com/utmstack/correlation-rules',
                       help='UTMStack correlation rules repository URL')
    parser.add_argument('--technology', '-t', type=str, help='Import rules for specific technology only')
    parser.add_argument('--limit', '-l', type=int, default=0, help='Limit total rules to process (0 = no limit)')
    parser.add_argument('--skip-update', action='store_true', help='Skip repository update')
    args = parser.parse_args()
    
    logger.info("Starting rule import from UTMStack correlation repository")
    
    # Set up paths
    repo_path = BASE_DIR / "utmstack_correlation_repo"
    structure_file = BASE_DIR / "utmstack_repo_structure.txt"
    
    # Clone or update repository
    if not args.skip_update:
        if not clone_or_update_repo(args.repo_url, repo_path):
            logger.error("Failed to clone/update repository")
            return
    
    # Explore repository and find rule files
    logger.info(f"Exploring repository: {repo_path}")
    tech_rules = explore_utmstack_repo(repo_path, structure_file)
    
    if not tech_rules:
        logger.warning("No rule files found in repository")
        return
    
    # Filter by technology if specified
    if args.technology:
        if args.technology in tech_rules:
            tech_rules = {args.technology: tech_rules[args.technology]}
            logger.info(f"Filtering to technology: {args.technology}")
        else:
            logger.error(f"Technology '{args.technology}' not found in repository")
            logger.info(f"Available technologies: {', '.join(tech_rules.keys())}")
            return
    
    # Track import statistics
    total_rules = sum(len(rules) for rules in tech_rules.values())
    processed = 0
    imported = 0
    duplicates = 0
    errors = 0
    import_log = []
    
    # Process each technology
    for tech_name, rule_files in tech_rules.items():
        logger.info(f"\nProcessing technology: {tech_name} ({len(rule_files)} rules)")
        
        # Apply limit if specified
        rules_to_process = rule_files
        if args.limit > 0 and processed >= args.limit:
            break
        elif args.limit > 0:
            remaining = args.limit - processed
            rules_to_process = rule_files[:remaining]
        
        # Process each rule file
        for rule_file in rules_to_process:
            processed += 1
            logger.info(f"\n[{processed}/{total_rules}] Processing: {rule_file.name}")
            
            # Analyze and potentially import the rule
            status, created_file = await analyze_and_import_rule(
                rule_file,
                tech_name,
                str(BASE_DIR)
            )
            
            # Track results
            if status == 'imported':
                imported += 1
                import_log.append({
                    'tech': tech_name,
                    'rule': rule_file.name,
                    'status': 'imported',
                    'file': created_file
                })
            elif status == 'duplicate':
                duplicates += 1
                import_log.append({
                    'tech': tech_name,
                    'rule': rule_file.name,
                    'status': 'duplicate',
                    'file': None
                })
            else:
                errors += 1
                import_log.append({
                    'tech': tech_name,
                    'rule': rule_file.name,
                    'status': 'error',
                    'file': None
                })
            
            # Delay between rules to avoid rate limiting
            if processed < total_rules and (args.limit == 0 or processed < args.limit):
                await asyncio.sleep(3)
    
    # Generate import report
    report_file = BASE_DIR / "import_report.txt"
    with open(report_file, 'w') as f:
        f.write("UTMSTACK RULE IMPORT REPORT\n")
        f.write(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Repository: {args.repo_url}\n")
        f.write(f"Total rules in repo: {total_rules}\n")
        f.write(f"Rules processed: {processed}\n")
        f.write(f"Rules imported: {imported}\n")
        f.write(f"Duplicates found: {duplicates}\n")
        f.write(f"Errors: {errors}\n\n")
        
        f.write("Import Details:\n")
        f.write("=" * 80 + "\n")
        for entry in import_log:
            f.write(f"\nTechnology: {entry['tech']}\n")
            f.write(f"Rule: {entry['rule']}\n")
            f.write(f"Status: {entry['status']}\n")
            if entry['file']:
                f.write(f"Created: {entry['file']}\n")
    
    logger.info("\n" + "=" * 80)
    logger.info("IMPORT SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Total rules processed: {processed}")
    logger.info(f"Successfully imported: {imported}")
    logger.info(f"Duplicates skipped: {duplicates}")
    logger.info(f"Errors: {errors}")
    logger.info(f"\nReports saved:")
    logger.info(f"  - Repository structure: {structure_file}")
    logger.info(f"  - Import report: {report_file}")

if __name__ == "__main__":
    # Use anyio for better async compatibility
    anyio.run(main)