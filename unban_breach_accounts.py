#!/usr/bin/env python3
"""
UG Security Breach - Meta Device Unban Script
==============================================

This script revokes Meta device bans that were incorrectly issued during the 
Meta App secret breach. It queries Meta's API directly to get ALL active device 
bans, filters by the attack time window, and revokes them.

Two modes:
  1. API mode (default): Fetches all bans from Meta, filters by date/time
  2. Logs mode (--logs): Uses Vercel logs to find affected devices

Usage:
    # Fetch from Meta API and unban devices banned in last hour
    python unban_breach_accounts.py --hours 1 --dry-run

    # Fetch from Meta API and unban devices banned since specific time  
    python unban_breach_accounts.py --since "2026-01-09T05:00:00" --dry-run

    # Use Vercel logs instead of API
    python unban_breach_accounts.py --logs logs_result.json --dry-run

Environment Variables Required:
    META_ACCESS_TOKEN   - Meta/Oculus app access token

Author: Generated for UG breach remediation
Date: January 2026
"""

import json
import os
import sys
import time
import argparse
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

META_API_DELAY = 0.5      # Seconds between Meta API calls
MAX_RETRIES = 3
RETRY_DELAY = 2

# ============================================================================
# META API - FETCH ALL DEVICE BANS
# ============================================================================

def fetch_all_device_bans(access_token: str) -> list[dict]:
    """
    Fetch all active device bans from Meta API.
    
    Returns list of dicts with:
        - ban_id: The ban ID (used for unbanning)
        - creation_date: When the ban was created (YYYY-MM-DD format)
    """
    url = f'https://graph.oculus.com/platform_integrity/device_ban_ids'
    params = {'access_token': access_token}
    
    all_bans = []
    
    while url:
        try:
            resp = requests.get(url, params=params, timeout=30)
            
            if not resp.ok:
                error_data = resp.json() if resp.text else {}
                error_msg = error_data.get('error', {}).get('message', f'HTTP {resp.status_code}')
                print(f"Error fetching bans: {error_msg}")
                return all_bans
            
            data = resp.json()
            
            # Extract bans from response
            for item in data.get('data', []):
                if item.get('message') == 'Success':
                    for ban in item.get('all_ban_ids', []):
                        all_bans.append({
                            'ban_id': ban.get('ban_id'),
                            'creation_date': ban.get('creation_date')
                        })
            
            # Check for pagination
            paging = data.get('paging', {})
            next_url = paging.get('next')
            
            if next_url:
                url = next_url
                params = {}  # Next URL includes all params
                time.sleep(0.5)  # Rate limit
            else:
                url = None
                
        except Exception as e:
            print(f"Exception fetching bans: {e}")
            break
    
    return all_bans


def filter_bans_by_window(bans: list[dict], since: datetime = None, hours: float = None) -> list[dict]:
    """
    Filter bans to only those created within the attack window.
    
    Note: Meta API only provides creation_date (YYYY-MM-DD), not exact time.
    So we filter by date and may include some bans from earlier in the day.
    """
    if hours:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
    
    if not since:
        return bans  # No filter
    
    since_date = since.date()
    
    filtered = []
    for ban in bans:
        try:
            ban_date = datetime.strptime(ban['creation_date'], '%Y-%m-%d').date()
            # Include bans from the attack date and after
            if ban_date >= since_date:
                filtered.append(ban)
        except (ValueError, TypeError):
            # If we can't parse the date, include it to be safe
            filtered.append(ban)
    
    return filtered


# ============================================================================
# DATA EXTRACTION FROM LOGS (fallback mode)
# ============================================================================

def extract_ban_data_from_logs(logs_file: str) -> list[dict]:
    """
    Extract ban data from Vercel logs JSON file.
    """
    with open(logs_file, 'r') as f:
        logs = json.load(f)
    
    ban_data = {}
    for entry in logs:
        msg = entry.get('message', '')
        if '[META DEVICE BAN] Success' not in msg:
            continue
            
        meta_match = re.search(r'MetaId:(\d+)', msg)
        unique_match = re.search(r'UniqueId:([a-f0-9]+)', msg)
        ban_id_match = re.search(r'BanId:([A-Za-z0-9]+)', msg)
        
        if unique_match and ban_id_match:
            unique_id = unique_match.group(1)
            timestamp = entry.get('TimeUTC', '')
            # Extract date from timestamp (format: "2026-01-09 05:23:48")
            creation_date = timestamp.split(' ')[0] if timestamp else 'unknown'
            
            ban_data[unique_id] = {
                'ban_id': ban_id_match.group(1),
                'meta_id': meta_match.group(1) if meta_match else None,
                'unique_id': unique_id,
                'timestamp': timestamp,
                'creation_date': creation_date
            }
    
    return list(ban_data.values())


# ============================================================================
# META API - REVOKE BAN
# ============================================================================

def revoke_device_ban(ban_id: str, access_token: str, dry_run: bool = False) -> dict:
    """
    Revoke a device ban using the ban_id.
    
    Returns dict with 'success', 'error' keys
    """
    if dry_run:
        return {'success': True, 'dry_run': True}
    
    url = 'https://graph.oculus.com/platform_integrity/device_ban'
    params = {
        'method': 'POST',
        'ban_id': ban_id,
        'is_banned': 'false',
        'remaining_time_in_minute': 0,
        'access_token': access_token
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.get(url, params=params, timeout=10)
            data = resp.json() if resp.text else {}
            
            if resp.ok and data.get('message') == 'Success':
                return {'success': True}
            else:
                error = data.get('error', {}).get('message', f'HTTP {resp.status_code}')
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                return {'success': False, 'error': error}
                
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                continue
            return {'success': False, 'error': 'Request timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    return {'success': False, 'error': 'Max retries exceeded'}


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Unban Meta devices affected by UG security breach',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check how many devices were banned today (safe - no changes)
  $env:META_ACCESS_TOKEN = "OC|app_id|token"
  python unban_breach_accounts.py --today --check

  # Check bans in the last hour
  python unban_breach_accounts.py --hours 1 --check

  # Actually unban devices banned in the last hour
  python unban_breach_accounts.py --hours 1

  # Unban all devices banned today
  python unban_breach_accounts.py --today

  # Use Vercel logs instead of querying Meta API
  python unban_breach_accounts.py --logs logs_result.json
        """
    )
    
    # Source options (mutually exclusive)
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--logs', '-l', metavar='FILE',
                        help='Use Vercel logs file instead of Meta API')
    source.add_argument('--hours', type=float,
                        help='Unban devices banned in the last N hours')
    source.add_argument('--since', metavar='DATETIME',
                        help='Unban devices banned since this time (ISO format)')
    source.add_argument('--today', action='store_true',
                        help='Unban all devices banned today')
    
    parser.add_argument('--check', '-c', action='store_true',
                        help='Just check/count bans without revoking (safe to run)')
    parser.add_argument('--dry-run', '-n', action='store_true',
                        help='Preview without making API calls')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Save results to JSON file')
    parser.add_argument('--limit', type=int,
                        help='Limit number of unbans')
    
    args = parser.parse_args()
    
    # Get token (not required for logs+check mode)
    meta_token = os.environ.get('META_ACCESS_TOKEN')
    
    needs_token = not args.logs or not args.check
    if not meta_token and needs_token and not args.dry_run:
        print("Error: META_ACCESS_TOKEN environment variable required")
        print("\nSet it with:")
        print('  PowerShell: $env:META_ACCESS_TOKEN = "OC|app_id|token"')
        print('  Bash:       export META_ACCESS_TOKEN="OC|app_id|token"')
        sys.exit(1)
    
    if not meta_token:
        meta_token = 'NOT_SET'
    
    # Determine source and get bans
    if args.logs:
        # Mode 1: From Vercel logs
        if not Path(args.logs).exists():
            print(f"Error: Logs file not found: {args.logs}")
            sys.exit(1)
        
        print(f"Loading bans from Vercel logs: {args.logs}")
        bans = extract_ban_data_from_logs(args.logs)
        print(f"Found {len(bans)} device bans in logs")
        
    else:
        # Mode 2: From Meta API
        print("Fetching all active device bans from Meta API...")
        
        if args.dry_run and meta_token == 'DRY_RUN_TOKEN':
            print("\n*** DRY RUN: Skipping API fetch (no token). Use --logs for dry run testing. ***")
            sys.exit(0)
        
        all_bans = fetch_all_device_bans(meta_token)
        print(f"Found {len(all_bans)} total active device bans")
        
        # Filter by time window
        if args.hours:
            since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
            print(f"Filtering to bans since: {since.isoformat()}")
        elif args.since:
            since = datetime.fromisoformat(args.since.replace('Z', '+00:00'))
            print(f"Filtering to bans since: {since.isoformat()}")
        elif args.today:
            since = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            print(f"Filtering to bans since: {since.isoformat()}")
        else:
            print("\nWarning: No time filter specified. This will unban ALL active device bans!")
            print("Use --hours, --since, or --today to filter.")
            confirm = input("Continue anyway? (yes/no): ")
            if confirm.lower() != 'yes':
                sys.exit(0)
            since = None
        
        bans = filter_bans_by_window(all_bans, since=since)
        print(f"Filtered to {len(bans)} bans within attack window")
    
    if not bans:
        print("No bans found in the specified window!")
        sys.exit(0)
    
    # Check mode - just display info and exit
    if args.check:
        print(f"\n{'='*70}")
        print(f"FOUND {len(bans)} DEVICE BANS")
        print(f"{'='*70}")
        
        # Group by date if we have creation_date
        by_date = {}
        for ban in bans:
            date = ban.get('creation_date', 'unknown')
            by_date[date] = by_date.get(date, 0) + 1
        
        if by_date:
            print("\nBans by date:")
            for date, count in sorted(by_date.items(), reverse=True):
                print(f"  {date}: {count} bans")
        
        print(f"\nTo revoke these bans, run without --check flag")
        
        # Save list if output specified
        if args.output:
            report = {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'check_only': True,
                'total_bans': len(bans),
                'by_date': by_date,
                'bans': bans
            }
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Ban list saved to: {args.output}")
        
        sys.exit(0)
    
    # Apply limit
    if args.limit:
        bans = bans[:args.limit]
        print(f"Limiting to {args.limit} bans")
    
    if args.dry_run:
        print("\n*** DRY RUN MODE - No actual unbans will occur ***\n")
    
    # Process unbans
    results = []
    success_count = 0
    fail_count = 0
    
    print(f"\nRevoking {len(bans)} device bans...\n")
    print("-" * 70)
    
    for i, ban in enumerate(bans):
        ban_id = ban['ban_id']
        idx = i + 1
        
        # Display info
        display_id = ban.get('meta_id') or ban.get('creation_date') or ban_id[:16]
        print(f"[{idx}/{len(bans)}] BanId: {ban_id[:20]}... ({display_id})", end=' ')
        
        result = revoke_device_ban(ban_id, meta_token, args.dry_run)
        result['ban_id'] = ban_id
        result['creation_date'] = ban.get('creation_date')
        result['meta_id'] = ban.get('meta_id')
        results.append(result)
        
        if result.get('success'):
            success_count += 1
            print("✓ REVOKED")
        else:
            fail_count += 1
            print(f"✗ FAILED - {result.get('error')}")
        
        if not args.dry_run:
            time.sleep(META_API_DELAY)
    
    print("-" * 70)
    print(f"\nSummary:")
    print(f"  Total processed: {len(bans)}")
    print(f"  Successfully revoked: {success_count}")
    print(f"  Failed: {fail_count}")
    
    if fail_count > 0:
        print(f"\nFailed bans:")
        for r in results:
            if not r.get('success'):
                print(f"  BanId: {r['ban_id'][:20]}... - {r.get('error')}")
    
    # Save report
    if args.output:
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'dry_run': args.dry_run,
            'source': 'logs' if args.logs else 'meta_api',
            'total_processed': len(bans),
            'success_count': success_count,
            'fail_count': fail_count,
            'results': results
        }
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nResults saved to: {args.output}")
    
    if fail_count > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()