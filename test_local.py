"""
Test script for AI Code Remediation Microservice
"""
import httpx
import json
import time
from typing import List, Dict


# Test cases with vulnerable code
TEST_CASES = [
    {
        "name": "SQL Injection (Python)",
        "language": "python",
        "cwe": "CWE-89",
        "vulnerable_code": """
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
"""
    },
    {
        "name": "XSS Vulnerability (JavaScript)",
        "language": "javascript",
        "cwe": "CWE-79",
        "vulnerable_code": """
function displayMessage(msg) {
    document.getElementById('output').innerHTML = msg;
}

// Usage
displayMessage(userInput);
"""
    },
    {
        "name": "Path Traversal (Python)",
        "language": "python",
        "cwe": "CWE-22",
        "vulnerable_code": """
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    return send_file(f'/var/data/{filename}')
"""
    },
    {
        "name": "Command Injection (Python)",
        "language": "python",
        "cwe": "CWE-78",
        "vulnerable_code": """
import os

def ping_host(hostname):
    command = f"ping -c 1 {hostname}"
    os.system(command)
"""
    },
    {
        "name": "Hard-coded Credentials (Python)",
        "language": "python",
        "cwe": "CWE-798",
        "vulnerable_code": """
def connect_to_database():
    username = "admin"
    password = "password123"
    return pymysql.connect(
        host='localhost',
        user=username,
        password=password,
        database='mydb'
    )
"""
    },
    {
        "name": "Insecure Deserialization (Python)",
        "language": "python",
        "cwe": "CWE-502",
        "vulnerable_code": """
import pickle

def load_user_data(data):
    user_obj = pickle.loads(data)
    return user_obj
"""
    }
]


def test_endpoint(base_url: str, test_case: Dict, verbose: bool = True):
    """
    Test a single vulnerability case.
    
    Args:
        base_url: Base URL of the service
        test_case: Test case dictionary
        verbose: Whether to print detailed output
    
    Returns:
        Result dictionary with metrics
    """
    endpoint = f"{base_url}/local_fix"
    
    payload = {
        "language": test_case["language"],
        "cwe": test_case["cwe"],
        "vulnerable_code": test_case["vulnerable_code"],
        "use_rag": True
    }
    
    if verbose:
        print(f"\n{'='*80}")
        print(f"Test Case: {test_case['name']}")
        print(f"{'='*80}")
        print(f"Language: {test_case['language']}")
        print(f"CWE: {test_case['cwe']}")
        print(f"\nVulnerable Code:")
        print(test_case["vulnerable_code"])
    
    try:
        start_time = time.time()
        
        with httpx.Client(timeout=120.0) as client:
            response = client.post(endpoint, json=payload)
        
        request_time = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            
            if verbose:
                print(f"\n{'-'*80}")
                print("Fixed Code:")
                print(result["fixed_code"])
                print(f"\n{'-'*80}")
                print("Diff:")
                print(result["diff"])
                print(f"\n{'-'*80}")
                print("Explanation:")
                print(result["explanation"])
                print(f"\n{'-'*80}")
                print("Metrics:")
                print(f"  Model: {result['model_name']}")
                print(f"  Input Tokens: {result['input_tokens']}")
                print(f"  Output Tokens: {result['output_tokens']}")
                print(f"  Total Tokens: {result['total_tokens']}")
                print(f"  Server Latency: {result['latency_ms']:.2f}ms")
                print(f"  Total Request Time: {request_time*1000:.2f}ms")
            
            return {
                "success": True,
                "test_case": test_case["name"],
                "latency_ms": result["latency_ms"],
                "total_request_ms": request_time * 1000,
                "input_tokens": result["input_tokens"],
                "output_tokens": result["output_tokens"],
                "total_tokens": result["total_tokens"],
                "model_name": result["model_name"]
            }
        else:
            print(f"\nError: {response.status_code}")
            print(response.text)
            return {
                "success": False,
                "test_case": test_case["name"],
                "error": response.text
            }
    
    except Exception as e:
        print(f"\nException: {e}")
        return {
            "success": False,
            "test_case": test_case["name"],
            "error": str(e)
        }


def run_all_tests(base_url: str = "http://localhost:8000", verbose: bool = True):
    """
    Run all test cases and generate summary.
    
    Args:
        base_url: Base URL of the service
        verbose: Whether to print detailed output
    """
    print("="*80)
    print("AI Code Remediation Microservice - Test Suite")
    print("="*80)
    
    # Check service health
    print("\nChecking service health...")
    try:
        with httpx.Client(timeout=10.0) as client:
            health_response = client.get(f"{base_url}/health")
        
        if health_response.status_code == 200:
            health_data = health_response.json()
            print(f"✓ Service is healthy")
            print(f"  Model: {health_data['model_name']}")
            print(f"  RAG Enabled: {health_data['rag_enabled']}")
            print(f"  RAG Documents: {health_data['rag_documents']}")
        else:
            print(f"✗ Service health check failed: {health_response.status_code}")
            return
    except Exception as e:
        print(f"✗ Cannot connect to service: {e}")
        return
    
    # Run tests
    results = []
    for test_case in TEST_CASES:
        result = test_endpoint(base_url, test_case, verbose=verbose)
        results.append(result)
        time.sleep(1)  # Brief pause between tests
    
    # Generate summary
    print("\n" + "="*80)
    print("Test Summary")
    print("="*80)
    
    successful = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]
    
    print(f"\nTotal Tests: {len(results)}")
    print(f"Passed: {len(successful)}")
    print(f"Failed: {len(failed)}")
    
    if successful:
        avg_latency = sum(r["latency_ms"] for r in successful) / len(successful)
        avg_tokens = sum(r["total_tokens"] for r in successful) / len(successful)
        total_time = sum(r["total_request_ms"] for r in successful)
        
        print(f"\nPerformance Metrics (Successful Tests):")
        print(f"  Average Server Latency: {avg_latency:.2f}ms")
        print(f"  Average Total Tokens: {avg_tokens:.0f}")
        print(f"  Total Processing Time: {total_time/1000:.2f}s")
    
    if failed:
        print(f"\nFailed Tests:")
        for r in failed:
            print(f"  - {r['test_case']}: {r.get('error', 'Unknown error')}")
    
    # Save results to file
    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed results saved to: test_results.json")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test AI Code Remediation Microservice")
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Base URL of the microservice (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal output (summary only)"
    )
    
    args = parser.parse_args()
    
    run_all_tests(base_url=args.url, verbose=not args.quiet)
