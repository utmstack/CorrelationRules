#!/usr/bin/env python3
"""
Generate correlation rules for a new technology in UTMStack using Claude Code SDK
This script analyzes a new technology folder, generates a list of rules,
appends them to ruleslist.md, and creates the actual rule files.
"""

import os
import sys
import time
import logging
import asyncio
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import anyio
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

# Base directory for correlation rules
BASE_DIR = Path(__file__).parent.absolute()

def find_filter_file(category: str, tech_name: str) -> Optional[str]:
    """
    Try to find a filter file for the technology
    """
    # Import the technology mappings from the main generation script
    try:
        from generate_correlation_rules import get_technology_mappings
        tech_mappings = get_technology_mappings()
        
        # Check if this technology exists in mappings
        if category in tech_mappings:
            for tech, filter_path in tech_mappings[category]:
                if tech == tech_name and filter_path:
                    full_path = BASE_DIR / filter_path
                    if full_path.exists():
                        return filter_path
    except:
        pass
    
    # Check common patterns
    possible_paths = [
        f"filters_from_github/{category}/{tech_name}.yml",
        f"filters_from_github/{category}/{tech_name}.yaml",
        f"filters_from_github/{tech_name}/{tech_name}.yml",
        f"filters_from_github/{tech_name}.yml",
    ]
    
    # Also check with underscores replaced by hyphens and vice versa
    alt_name = tech_name.replace('_', '-') if '_' in tech_name else tech_name.replace('-', '_')
    possible_paths.extend([
        f"filters_from_github/{category}/{alt_name}.yml",
        f"filters_from_github/{alt_name}/{alt_name}.yml",
    ])
    
    for path in possible_paths:
        full_path = BASE_DIR / path
        if full_path.exists():
            return path
    
    return None

def analyze_technology_folder(tech_path: Path) -> Tuple[str, str, Optional[str]]:
    """
    Analyze a technology folder to determine category, name, and filter file
    Returns: (category, technology_name, filter_path)
    """
    # Get the folder name and parent
    tech_name = tech_path.name
    category = tech_path.parent.name
    
    # Handle case where tech_path is directly under BASE_DIR
    if tech_path.parent == BASE_DIR:
        category = tech_name  # Use tech_name as category
        logger.warning(f"Technology folder is at root level, using '{tech_name}' as both category and technology name")
    
    # Find filter file
    filter_path = find_filter_file(category, tech_name)
    
    return category, tech_name, filter_path

async def generate_rules_list(tech_name: str, category: str, filter_path: Optional[str]) -> List[str]:
    """
    Use Claude to generate a list of correlation rules for the technology
    """
    prompt = f"""You are tasked with generating a comprehensive list of correlation rules for a new technology: {tech_name} (category: {category}).

IMPORTANT: Generate a list of correlation rules that a SIEM should have for this technology.

Consider the following aspects:
1. Common security threats and attacks specific to this technology
2. Compliance and audit requirements
3. Performance and availability monitoring
4. Configuration security
5. Access control and authentication
6. Data protection and privacy
7. Integration with other systems
8. Technology-specific vulnerabilities

{"Filter file available at: " + filter_path if filter_path else "No specific filter file available"}

Generate a list of 20-30 correlation rules in the following format (just the rule names, one per line):
- Rule name 1
- Rule name 2
- etc.

Focus on practical, actionable rules that would help detect real security incidents.
Output ONLY the bullet list of rules, nothing else."""

    try:
        logger.info(f"Generating rules list for {tech_name}")
        
        # Configure options for Claude Code
        options = ClaudeCodeOptions(
            max_turns=1,
            cwd=str(BASE_DIR),
            permission_mode="acceptEdits"
        )
        
        rules = []
        
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        # Extract rules from the response
                        lines = block.text.strip().split('\n')
                        for line in lines:
                            line = line.strip()
                            if line.startswith('- ') and len(line) > 2:
                                rules.append(line[2:].strip())
        
        logger.info(f"Generated {len(rules)} rules for {tech_name}")
        return rules
        
    except Exception as e:
        logger.error(f"Error generating rules list: {str(e)}")
        return []

def append_to_ruleslist(tech_name: str, category: str, rules: List[str]) -> bool:
    """
    Append the new technology rules to ruleslist.md
    """
    ruleslist_path = BASE_DIR / "ruleslist.md"
    
    try:
        # Read current content
        with open(ruleslist_path, 'r') as f:
            content = f.read()
        
        # Create the new section
        section_title = tech_name.replace('_', ' ').replace('-', ' ').title()
        new_section = f"\n\n### {category.upper()} - {section_title}\n"
        
        for rule in rules:
            new_section += f"- {rule}\n"
        
        # Append to file
        with open(ruleslist_path, 'a') as f:
            f.write(new_section)
        
        logger.info(f"Added {len(rules)} rules to ruleslist.md for {tech_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error updating ruleslist.md: {str(e)}")
        return False

def create_claude_prompt(tech_name: str, tech_folder: str, filter_path: str, rules: List[str], batch_num: int = 1, total_batches: int = 1) -> str:
    """
    Create a detailed prompt for Claude to generate correlation rules
    (Reused from generate_correlation_rules.py with minor modifications)
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
5. Save each rule as a separate YAML file in the folder: {tech_folder}
6. Name each file descriptively based on the rule, e.g., "brute_force_detection.yml", "malware_outbreak.yml"
7. Each rule file should contain a single rule in the correct YAML format
8. Use appropriate CEL expressions in the 'where' field based on actual vendor field names
9. Set realistic impact scores (confidentiality, integrity, availability) from 0-5
10. Include relevant references where applicable (vendor docs and MITRE ATT&CK)
11. Use the "safe" function for fields that might not exist
12. Fields not from filters should start with "log."
13. Start rule IDs from {4000 + (batch_num - 1) * len(rules) + 1}

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
- id: {4000 + (batch_num - 1) * len(rules) + 1}
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

Please create the correlation rules now. Start with the first rule and save it to the appropriate file."""
    
    return prompt

async def run_claude_code(prompt: str, working_dir: str) -> bool:
    """
    Run Claude Code SDK with the given prompt
    (Reused from generate_correlation_rules.py)
    """
    try:
        logger.info(f"Running Claude Code SDK for directory: {working_dir}")
        
        # Configure options for Claude Code
        options = ClaudeCodeOptions(
            max_turns=10,  # Allow multiple turns for creating multiple files
            cwd=working_dir,
            allowed_tools=["Read", "Write", "MultiEdit", "Grep", "Glob", "WebSearch"],
            permission_mode="acceptEdits"  # Automatically accept edits
        )
        
        messages = []
        result = None
        
        async for message in query(prompt=prompt, options=options):
            messages.append(message)
            
            # Log assistant messages
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        logger.debug(f"Claude: {block.text[:100]}...")
            
            # Capture the final result
            if isinstance(message, ResultMessage):
                result = message
                if hasattr(result, 'cost_cents'):
                    logger.debug(f"Task completed. Cost: {result.cost_cents/100:.2f} USD")
                else:
                    logger.debug("Task completed successfully")
        
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
    Main function to orchestrate rule generation for new technology
    """
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Generate correlation rules for a new technology')
    parser.add_argument('tech_path', type=str, help='Path to the new technology folder')
    parser.add_argument('--skip-list', action='store_true', help='Skip generating rules list (use existing from ruleslist.md)')
    parser.add_argument('--batch-size', '-b', type=int, default=5, help='Number of rules per batch (default: 5)')
    args = parser.parse_args()
    
    # Validate technology path
    tech_path = Path(args.tech_path)
    if not tech_path.is_absolute():
        tech_path = BASE_DIR / tech_path
    
    if not tech_path.exists() or not tech_path.is_dir():
        logger.error(f"Technology folder not found: {tech_path}")
        return
    
    logger.info(f"Processing new technology: {tech_path}")
    
    # Analyze technology folder
    category, tech_name, filter_path = analyze_technology_folder(tech_path)
    logger.info(f"Category: {category}, Technology: {tech_name}")
    if filter_path:
        logger.info(f"Filter file: {filter_path}")
    else:
        logger.warning("No filter file found for this technology")
    
    # Generate or retrieve rules list
    if args.skip_list:
        # Read existing rules from ruleslist.md
        logger.info("Reading existing rules from ruleslist.md")
        from generate_correlation_rules import get_rules_for_technology
        rules = get_rules_for_technology(tech_name)
        
        if not rules:
            logger.error(f"No rules found in ruleslist.md for {tech_name}")
            return
    else:
        # Generate new rules list
        rules = await generate_rules_list(tech_name, category, filter_path)
        
        if not rules:
            logger.error("Failed to generate rules list")
            return
        
        # Append to ruleslist.md
        if not append_to_ruleslist(tech_name, category, rules):
            logger.error("Failed to append rules to ruleslist.md")
            return
    
    logger.info(f"Found {len(rules)} rules for {tech_name}")
    
    # Create rules in batches
    batch_size = args.batch_size
    total_batches = (len(rules) + batch_size - 1) // batch_size
    
    tech_success = True
    for batch_num in range(1, total_batches + 1):
        start_idx = (batch_num - 1) * batch_size
        end_idx = min(batch_num * batch_size, len(rules))
        batch_rules = rules[start_idx:end_idx]
        
        if total_batches > 1:
            logger.info(f"Processing batch {batch_num}/{total_batches} for {tech_name} ({len(batch_rules)} rules)")
        
        # Full filter path if it exists
        full_filter_path = BASE_DIR / filter_path if filter_path else None
        
        # Create prompt for this batch
        prompt = create_claude_prompt(
            tech_name=tech_name,
            tech_folder=str(tech_path),
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
            break
        else:
            logger.info(f"Successfully generated rules for {tech_name} (batch {batch_num})")
        
        # Delay between batches
        if batch_num < total_batches:
            await asyncio.sleep(2)
    
    # Summary
    if tech_success:
        logger.info(f"\nSuccessfully generated all rules for {tech_name}")
        logger.info(f"Rules location: {tech_path}/")
        if not args.skip_list:
            logger.info(f"Rules list added to: ruleslist.md")
    else:
        logger.error(f"\nFailed to generate all rules for {tech_name}")

if __name__ == "__main__":
    # Use anyio for better async compatibility
    anyio.run(main)