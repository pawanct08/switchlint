import subprocess
import yaml
import json
import sys
import os

def run_test(case_path):
    print(f"Running test: {case_path}")
    with open(case_path, 'r') as f:
        case = yaml.safe_load(f)
    
    # Path is relative to the test case file or absolute
    topo_path = case['topology']
    if not os.path.isabs(topo_path):
        topo_path = os.path.join(os.path.dirname(case_path), topo_path)
        
    expected = case['expect']
    
    # Run switchlint
    import platform
    exe_name = "switchlint.exe" if platform.system() == "Windows" else "switchlint"
    exe = os.path.join(os.getcwd(), "build", exe_name)
    cmd = [exe, "--format", "json", topo_path]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # switchlint returns 1 if there are errors/warnings (with --fail-on-warn)
    # So we accept 0 or 1.
    if result.returncode not in [0, 1]:
        print(f"[FAIL] {case_path}: switchlint crashed or returned error {result.returncode}")
        print("STDERR:", result.stderr)
        return False
    
    try:
        actual_root = json.loads(result.stdout)
        actual = actual_root.get('violations', [])
    except json.JSONDecodeError:
        print(f"[FAIL] {case_path}: Failed to parse JSON output")
        print("STDOUT:", result.stdout)
        return False
    
    # Compare
    # Case: No violations expected
    if not expected:
        if actual:
            print(f"[FAIL] {case_path}: expected 0 violations, got {len(actual)}")
            for v in actual:
                print(f"  - [{v.get('severity', '???')}] {v.get('rule_id', '???')}: {v.get('message', '???')}")
            return False
        print(f"[PASS] {case_path}")
        return True

    # Case: Expectations present
    for exp in expected:
        found = False
        for act in actual:
            # Match fields. If an expected field is missing in act, it's an empty string.
            rule_match     = act['rule_id'] == exp['rule']
            stream_match   = act.get('stream_id', "") == exp.get('stream', "")
            node_match     = act.get('node_id', "")   == exp.get('node', "")
            port_match     = act.get('port_id', "")   == exp.get('port', "")
            # Severity in JSON is lowercase, in test case it might be uppercase.
            # Also handle WARNING vs WARN.
            act_sev = act['severity'].upper()
            if act_sev == "WARNING": act_sev = "WARN"
            
            exp_sev = exp['severity'].upper()
            if exp_sev == "WARNING": exp_sev = "WARN"

            severity_match = act_sev == exp_sev
            
            if rule_match and stream_match and node_match and port_match and severity_match:
                found = True
                break
        
        if not found:
            print(f"[FAIL] {case_path}: Expected violation not found: {exp}")
            # Optionally print actual violations for debugging
            # print("Actual violations:", actual)
            return False
            
    print(f"[PASS] {case_path}")
    return True

if __name__ == "__main__":
    test_dir = "tests/cases"
    if not os.path.exists(test_dir):
        print(f"Error: {test_dir} not found")
        sys.exit(1)
        
    cases = [os.path.join(test_dir, f) for f in os.listdir(test_dir) if f.endswith(".yaml")]
    
    if not cases:
        print("No test cases found.")
        sys.exit(0)
        
    all_pass = True
    for c in cases:
        if not run_test(c):
            all_pass = False
            
    if all_pass:
        print("\nAll integration tests passed!")
    else:
        print("\nSome integration tests failed.")
        
    sys.exit(0 if all_pass else 1)
