#!/usr/bin/env python3
"""
Verify and ground correlation rules for UTMStack using Claude Code SDK
This script verifies existing rules against vendor documentation and ensures
correct field usage and syntax compliance with rulesdoc.md
"""

import os
import sys
import time
import logging
import asyncio
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

# Base directory for correlation rules
BASE_DIR = Path(__file__).parent.absolute()

def get_all_rule_files() -> List[Path]:
    """
    Find all YAML rule files in the correlation rules directory
    """
    rule_files = []
    
    # Skip these directories
    skip_dirs = {'venv', '.git', '__pycache__', 'filters_from_github'}
    
    for root, dirs, files in os.walk(BASE_DIR):
        # Remove directories we want to skip
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for file in files:
            if file.endswith('.yml') and not file.startswith('.'):
                file_path = Path(root) / file
                # Skip filter files and other non-rule files
                if 'filters_from_github' not in str(file_path) and file != 'rulesdoc.md':
                    rule_files.append(file_path)
    
    return sorted(rule_files)

def extract_technology_from_path(file_path: Path) -> Tuple[str, str]:
    """
    Extract technology category and name from file path
    """
    parts = file_path.relative_to(BASE_DIR).parts
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "unknown", "unknown"

def get_filter_fields_for_technology(tech_category: str, tech_name: str) -> Tuple[Optional[str], List[str]]:
    """
    Get the filter fields for a given technology from the filter_fields_output.txt file
    Returns: (filter_file_name, list_of_fields)
    """
    # Import the mappings from the generation script to stay consistent
    from generate_correlation_rules import get_technology_mappings
    
    tech_mappings = get_technology_mappings()
    filter_file_name = None
    
    # Find the filter path for this technology
    if tech_category in tech_mappings:
        for tech, filter_path in tech_mappings[tech_category]:
            if tech == tech_name and filter_path:
                filter_file_name = filter_path
                break
    
    # Fallback to manual mappings for any missing ones
    if not filter_file_name:
        filter_mappings = {
            ("antivirus", "bitdefender_gz"): "filters_from_github/antivirus/bitdefender_gz.yml",
            ("antivirus", "sentinel-one"): "filters_from_github/antivirus/sentinel-one.yml",
            ("antivirus", "kaspersky"): "filters_from_github/antivirus/kaspersky.yml",
            ("antivirus", "esmc-eset"): "filters_from_github/antivirus/esmc-eset.yml",
            ("antivirus", "deceptive-bytes"): "filters_from_github/deceptivebytes/deceptive-bytes.yml",
            ("aws", "aws"): "filters_from_github/aws/aws.yml",
            ("cloud", "azure"): "filters_from_github/azure/azure-eventhub.yml",
            ("cloud", "google"): "filters_from_github/google/gcp.yml",
        }
        filter_file_name = filter_mappings.get((tech_category, tech_name))
    
    if not filter_file_name:
        return None, []
    
    # Extract just the relative path from filters_from_github
    if 'filters_from_github/' in filter_file_name:
        search_name = filter_file_name.split('filters_from_github/')[-1]
    else:
        search_name = filter_file_name
    
    # Remove ./ prefix if present
    if search_name.startswith('./'):
        search_name = search_name[2:]
    
    # Read the filter fields from the output file
    fields = []
    filter_fields_file = BASE_DIR / "filter_fields_output.txt"
    
    if not filter_fields_file.exists():
        logger.warning(f"Filter fields output file not found: {filter_fields_file}")
        return filter_file_name, []
    
    try:
        with open(filter_fields_file, 'r') as f:
            content = f.read()
        
        # Find the section for this filter file by looking for the exact file line
        file_marker = f"File: {search_name}"
        if file_marker in content:
            # Find the position of this file marker
            start_pos = content.find(file_marker)
            # Find the next file marker (or end of file)
            next_file_pos = content.find("\nFile:", start_pos + 1)
            if next_file_pos == -1:
                section = content[start_pos:]
            else:
                section = content[start_pos:next_file_pos]
            
            # Extract fields from this section
            lines = section.split('\n')
            in_fields_section = False
            for line in lines:
                if line.strip() == "Fields created:":
                    in_fields_section = True
                elif line.strip() == "Dynamic fields from JSON parsing:":
                    # We'll continue collecting fields but skip dynamic indicators
                    continue
                elif line.strip().startswith("=") and in_fields_section:
                    # End of section
                    break
                elif in_fields_section and line.strip().startswith("- "):
                    field = line.strip()[2:]  # Remove "- " prefix
                    if not field.startswith("*"):  # Skip dynamic field indicators
                        fields.append(field)
                
    except Exception as e:
        logger.error(f"Error reading filter fields: {e}")
        
    return filter_file_name, fields

def create_verification_prompt(rule_file: Path, tech_category: str, tech_name: str, filter_name: Optional[str], filter_fields: List[str]) -> str:
    """
    Create a detailed prompt for Claude to verify a correlation rule
    """
    fields_section = ""
    if filter_fields:
        fields_section = f"""
3. Available fields from the filter ({filter_name}):
{chr(10).join(f'   - {field}' for field in sorted(filter_fields))}
"""
    else:
        fields_section = "3. No filter fields information available for this technology"
    
    prompt = f"""You are tasked with verifying and grounding a correlation rule for {tech_name} in the UTMStack system.

IMPORTANT: Follow these verification steps EXACTLY:

1. Read the rule file at: {rule_file}
2. Read the rulesdoc.md file to understand the correct rule syntax and structure
{fields_section}
4. Use WebSearch to find vendor documentation for {tech_name} to verify:
   - Correct field names and values
   - Event types and their exact names/values
   - Log format examples
   - Search for: "{tech_name} log fields", "{tech_name} event types", "{tech_name} log examples", "{tech_name} syslog format"

5. Verify the following aspects of the rule:
   a) Syntax compliance with rulesdoc.md structure
   b) Field names match vendor documentation or available filter fields
   c) CEL expressions use correct field paths and values
   d) Event types and values are accurate per vendor docs
   e) Impact scores are appropriate for the threat
   f) References are valid and relevant
   g) Description is clear and accurate

6. Fix any issues found:
   - Correct field names to match vendor documentation
   - Fix CEL expression syntax
   - Update event type values to match actual log values
   - Ensure all fields use the "safe" function
   - Add proper next steps to the description

7. Enhance the description by adding a "Next Steps" section that includes:
   - Investigation steps for analysts
   - What to look for in related logs
   - Potential remediation actions

8. Save the corrected rule back to the same file using Write or MultiEdit

9. Create a verification report as a comment at the top of your response explaining:
   - What was checked
   - What issues were found (if any)
   - What changes were made
   - Confidence level in the rule accuracy

Technology: {tech_category}/{tech_name}
Rule file: {rule_file}
Filter: {filter_name if filter_name else "None"}

Please proceed with the verification now."""
    
    return prompt

async def verify_single_rule(rule_file: Path, working_dir: str) -> Tuple[bool, str]:
    """
    Verify a single correlation rule
    """
    try:
        # Extract technology info
        tech_category, tech_name = extract_technology_from_path(rule_file)
        filter_name, filter_fields = get_filter_fields_for_technology(tech_category, tech_name)
        
        logger.info(f"Verifying rule: {rule_file}")
        logger.debug(f"Technology: {tech_category}/{tech_name}")
        logger.debug(f"Filter: {filter_name}, Fields: {len(filter_fields)}")
        
        # Create verification prompt
        prompt = create_verification_prompt(rule_file, tech_category, tech_name, filter_name, filter_fields)
        
        # Configure options for Claude Code
        options = ClaudeCodeOptions(
            max_turns=10,  # Allow multiple turns for verification and fixes
            cwd=working_dir,
            allowed_tools=["Read", "Write", "MultiEdit", "WebSearch", "Grep"],
            permission_mode="acceptEdits"  # Automatically accept edits
        )
        
        messages = []
        result = None
        verification_report = ""
        
        async for message in query(prompt=prompt, options=options):
            messages.append(message)
            
            # Capture assistant messages for the report
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        # Look for verification report in the response
                        if "verification report" in block.text.lower() or block.text.startswith("##"):
                            verification_report += block.text + "\n"
                        logger.debug(f"Claude: {block.text[:100]}...")
            
            # Capture the final result
            if isinstance(message, ResultMessage):
                result = message
                if hasattr(result, 'cost_cents'):
                    logger.debug(f"Verification completed. Cost: {result.cost_cents/100:.2f} USD")
                else:
                    logger.debug("Verification completed successfully")
        
        logger.info(f"Successfully verified rule: {rule_file.name}")
        return True, verification_report
            
    except CLINotFoundError:
        error_msg = "Claude Code CLI not found. Please install: npm install -g @anthropic-ai/claude-code"
        logger.error(error_msg)
        return False, error_msg
    except ProcessError as e:
        error_msg = f"Claude Code process failed with exit code {e.exit_code}: {e.stderr}"
        logger.error(error_msg)
        return False, error_msg
    except CLIJSONDecodeError as e:
        error_msg = f"Failed to decode Claude Code response: {str(e)}"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error verifying rule: {str(e)}"
        logger.error(error_msg)
        return False, error_msg

async def main():
    """
    Main function to orchestrate rule verification
    """
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Verify UTMStack correlation rules')
    parser.add_argument('--file', '-f', type=str, help='Verify a specific rule file')
    parser.add_argument('--technology', '-t', type=str, help='Verify all rules for a specific technology (e.g., antivirus/bitdefender_gz)')
    parser.add_argument('--limit', '-l', type=int, default=0, help='Limit number of rules to verify (0 = no limit)')
    args = parser.parse_args()
    
    logger.info("Starting correlation rule verification")
    
    # Get rule files based on arguments
    if args.file:
        # Verify single file
        rule_file = Path(args.file)
        if not rule_file.is_absolute():
            rule_file = BASE_DIR / rule_file
        if not rule_file.exists():
            logger.error(f"Rule file not found: {rule_file}")
            return
        rule_files = [rule_file]
    elif args.technology:
        # Verify all rules for a technology
        tech_parts = args.technology.split('/')
        if len(tech_parts) != 2:
            logger.error("Technology must be in format: category/name (e.g., antivirus/bitdefender_gz)")
            return
        
        tech_dir = BASE_DIR / tech_parts[0] / tech_parts[1]
        if not tech_dir.exists():
            logger.error(f"Technology directory not found: {tech_dir}")
            return
        
        rule_files = list(tech_dir.glob("*.yml"))
    else:
        # Get all rule files
        rule_files = get_all_rule_files()
    
    # Apply limit if specified
    if args.limit > 0:
        rule_files = rule_files[:args.limit]
    
    logger.info(f"Found {len(rule_files)} rule files to verify")
    
    # Track verification results
    total_rules = len(rule_files)
    verified = 0
    failed = []
    reports = []
    
    # Process rules in batches of 5
    batch_size = 5
    total_batches = (total_rules + batch_size - 1) // batch_size  # Ceiling division
    
    for batch_num in range(1, total_batches + 1):
        start_idx = (batch_num - 1) * batch_size
        end_idx = min(batch_num * batch_size, total_rules)
        batch = rule_files[start_idx:end_idx]
        
        if total_batches > 1:
            logger.info(f"\nProcessing batch {batch_num}/{total_batches} (rules {start_idx + 1}-{end_idx} of {total_rules})")
        
        # Process batch concurrently
        batch_tasks = []
        for rule_file in batch:
            logger.info(f"  - {rule_file.relative_to(BASE_DIR)}")
            batch_tasks.append(verify_single_rule(rule_file, str(BASE_DIR)))
        
        # Wait for all tasks in batch to complete
        batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
        
        # Process batch results
        for rule_file, result in zip(batch, batch_results):
            if isinstance(result, Exception):
                # Handle exceptions
                failed.append(str(rule_file.relative_to(BASE_DIR)))
                reports.append({
                    'file': str(rule_file.relative_to(BASE_DIR)),
                    'status': 'failed',
                    'report': f"Exception: {str(result)}"
                })
            else:
                success, report = result
                if success:
                    verified += 1
                    reports.append({
                        'file': str(rule_file.relative_to(BASE_DIR)),
                        'status': 'verified',
                        'report': report
                    })
                else:
                    failed.append(str(rule_file.relative_to(BASE_DIR)))
                    reports.append({
                        'file': str(rule_file.relative_to(BASE_DIR)),
                        'status': 'failed',
                        'report': report
                    })
        
        # Delay between batches to avoid rate limiting
        if batch_num < total_batches:
            await asyncio.sleep(2)  # 2 seconds between batches, same as generate_correlation_rules.py
    
    # Generate summary report
    logger.info("\n" + "="*80)
    logger.info("VERIFICATION SUMMARY")
    logger.info("="*80)
    logger.info(f"Total rules processed: {total_rules}")
    logger.info(f"Successfully verified: {verified}")
    logger.info(f"Failed verifications: {len(failed)}")
    
    if failed:
        logger.error("\nFailed rules:")
        for rule in failed:
            logger.error(f"  - {rule}")
    
    # Save detailed report
    report_file = BASE_DIR / "verification_report.txt"
    with open(report_file, 'w') as f:
        f.write("CORRELATION RULES VERIFICATION REPORT\n")
        f.write(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*80 + "\n\n")
        
        for report in reports:
            f.write(f"File: {report['file']}\n")
            f.write(f"Status: {report['status']}\n")
            f.write("Report:\n")
            f.write(report['report'])
            f.write("\n" + "-"*80 + "\n\n")
    
    logger.info(f"\nDetailed report saved to: {report_file}")

if __name__ == "__main__":
    # Use anyio for better async compatibility
    anyio.run(main)