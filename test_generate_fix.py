#!/usr/bin/env python3
"""
Test script to verify the generate_correlation_rules.py improvements
"""
import subprocess
import sys
import time
from pathlib import Path

def run_test():
    """Run a quick test of the generation script"""
    print("Testing the improved generate_correlation_rules.py script...")
    
    # Run with verbose and retry flags on a single technology
    cmd = [
        sys.executable,
        "generate_correlation_rules.py",
        "--technology", "antivirus/bitdefender_gz",
        "--verbose",
        "--retry-failed"
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        print("\n=== STDOUT ===")
        print(result.stdout)
        
        if result.stderr:
            print("\n=== STDERR ===")
            print(result.stderr)
            
        print(f"\n=== Execution completed in {time.time() - start_time:.2f} seconds ===")
        
        # Check if generation_state.json was created
        state_file = Path("generation_state.json")
        if state_file.exists():
            print(f"\nState file created: {state_file}")
            with open(state_file, 'r') as f:
                print(f"State file contents: {f.read()}")
        
        # Check if any files were created
        target_dir = Path("antivirus/bitdefender_gz")
        if target_dir.exists():
            yml_files = list(target_dir.glob("*.yml"))
            print(f"\nFound {len(yml_files)} YAML files in {target_dir}")
            if yml_files:
                print("Files created:")
                for f in yml_files[:5]:
                    print(f"  - {f.name}")
                if len(yml_files) > 5:
                    print(f"  ... and {len(yml_files) - 5} more")
        
        return result.returncode == 0
        
    except Exception as e:
        print(f"\nError running test: {e}")
        return False

if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)