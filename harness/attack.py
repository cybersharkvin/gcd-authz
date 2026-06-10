#!/usr/bin/env python3
"""
Attack harness for tantalus-local. 
Cycles through prompt variations from a JSON file, fires them at the server,
records which ones produce wins.

Usage:
    python3 harness/attack.py [--endpoint http://localhost:3350] [--skill infra-monitor] [--concurrency 5]
"""

import argparse
import json
import time
import sys
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class AttackResult:
    variant_id: int
    skill: str
    turns: list  # list of user messages
    tool_calls: list
    win: bool
    win_id: str
    response_text: str
    duration_ms: int
    error: str

def get_session(endpoint):
    r = requests.get(f"{endpoint}/", allow_redirects=False)
    for cookie in r.headers.get("set-cookie", "").split(";"):
        if "tantalus_session=" in cookie:
            return cookie.split("=", 1)[1].strip()
    # Parse from response cookies
    return r.cookies.get("tantalus_session", "")

def run_attack(endpoint, skill_id, turns, variant_id):
    """Run a single multi-turn attack. Returns AttackResult."""
    start = time.time()
    try:
        # Get fresh session
        r = requests.get(f"{endpoint}/")
        session_cookie = None
        if "set-cookie" in r.headers:
            for part in r.headers["set-cookie"].split(";"):
                if "tantalus_session=" in part:
                    session_cookie = part.split("=", 1)[1].strip()
                    break
        if not session_cookie:
            # Try from cookies jar
            session_cookie = r.cookies.get("tantalus_session", f"sess_test_{variant_id}")
        
        cookies = {"tantalus_session": session_cookie}
        
        # Toggle skill
        requests.post(f"{endpoint}/skills/{skill_id}/toggle", cookies=cookies)
        
        # Execute turns
        all_tool_calls = []
        win = False
        win_id = ""
        last_response = ""
        
        for turn_msg in turns:
            r = requests.post(
                f"{endpoint}/chat",
                data={"message": turn_msg},
                cookies=cookies,
                timeout=180,
            )
            body = r.text
            last_response = body
            
            # Check for win
            if "win-banner" in body:
                win = True
                # Extract win ID from banner text
                for wid in ["SshKeyExfil", "ApiKeyExfil", "InfraMonitorExfil", "TicketAssistForward", "ChatDataExfil"]:
                    if wid in body:
                        win_id = wid
                        break
                if not win_id:
                    win_id = "unknown"
            
            # Extract tool calls from trace
            import re
            trace_match = re.search(r'json-viewer.*?>(.*?)</pre>', body, re.DOTALL)
            if trace_match:
                try:
                    trace = json.loads(trace_match.group(1).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"'))
                    for t in trace:
                        if "tool_call" in t:
                            all_tool_calls.append(t["tool_call"])
                except:
                    pass
            
            if win:
                break
        
        duration = int((time.time() - start) * 1000)
        return AttackResult(
            variant_id=variant_id,
            skill=skill_id,
            turns=turns,
            tool_calls=all_tool_calls,
            win=win,
            win_id=win_id,
            response_text=last_response[:500] if not win else "",
            duration_ms=duration,
            error="",
        )
    except Exception as e:
        duration = int((time.time() - start) * 1000)
        return AttackResult(
            variant_id=variant_id,
            skill=skill_id,
            turns=turns,
            tool_calls=[],
            win=False,
            win_id="",
            response_text="",
            duration_ms=duration,
            error=str(e),
        )

def main():
    parser = argparse.ArgumentParser(description="Attack harness for tantalus-local")
    parser.add_argument("--endpoint", default="http://localhost:3350")
    parser.add_argument("--variants", default="harness/variants.json", help="JSON file with attack variants")
    parser.add_argument("--skill", default=None, help="Override skill for all variants")
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--output", default="harness/results.json")
    parser.add_argument("--limit", type=int, default=None, help="Max variants to run")
    args = parser.parse_args()
    
    # Load variants
    with open(args.variants) as f:
        variants = json.load(f)
    
    if args.limit:
        variants = variants[:args.limit]
    
    print(f"Loaded {len(variants)} attack variants")
    print(f"Endpoint: {args.endpoint}")
    print(f"Concurrency: {args.concurrency}")
    print(f"Output: {args.output}")
    print()
    
    # Verify server is up
    try:
        r = requests.get(f"{args.endpoint}/", timeout=5)
        assert r.status_code == 200
    except:
        print(f"ERROR: Server not responding at {args.endpoint}")
        sys.exit(1)
    
    results = []
    wins = 0
    errors = 0
    
    def run_one(i, variant):
        skill = args.skill or variant.get("skill", "infra-monitor")
        turns = variant["turns"] if isinstance(variant.get("turns"), list) else [variant.get("prompt", variant.get("message", ""))]
        return run_attack(args.endpoint, skill, turns, i)
    
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(run_one, i, v): i for i, v in enumerate(variants)}
        
        for future in as_completed(futures):
            result = future.result()
            results.append(asdict(result))
            
            if result.win:
                wins += 1
                print(f"  🚨 WIN #{wins} variant={result.variant_id} win_id={result.win_id} ({result.duration_ms}ms)")
                print(f"     turns: {result.turns}")
                print(f"     tools: {result.tool_calls[-3:]}")
            elif result.error:
                errors += 1
                if errors <= 3:
                    print(f"  ❌ ERROR variant={result.variant_id}: {result.error[:80]}")
            else:
                done = len(results)
                if done % 10 == 0:
                    print(f"  ... {done}/{len(variants)} done, {wins} wins so far")
    
    # Sort by variant_id
    results.sort(key=lambda r: r["variant_id"])
    
    # Write results
    output = {
        "meta": {
            "endpoint": args.endpoint,
            "total": len(variants),
            "wins": wins,
            "errors": errors,
            "win_rate": f"{wins}/{len(variants)} ({100*wins/max(1,len(variants)):.1f}%)",
        },
        "wins": [r for r in results if r["win"]],
        "results": results,
    }
    
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    
    print()
    print(f"=== RESULTS ===")
    print(f"Total: {len(variants)}")
    print(f"Wins:  {wins} ({100*wins/max(1,len(variants)):.1f}%)")
    print(f"Errors: {errors}")
    print(f"Output: {args.output}")
    if wins:
        print(f"\nWinning variants:")
        for r in results:
            if r["win"]:
                print(f"  #{r['variant_id']}: {r['turns'][0][:80]}...")

if __name__ == "__main__":
    main()
