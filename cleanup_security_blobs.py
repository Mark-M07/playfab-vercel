#!/usr/bin/env python3
"""
UG Security Breach - PlayFab Security Blob Cleanup
===================================================

This script cleans up the Security blob data in PlayFab for accounts that were
falsely flagged during the security breach. 

The attacker added fake ban records to the Security blob with reason 
"PlayFab ban: Racism | Bullying | Hateful Behavior". This script identifies
accounts where this is the ONLY entry and clears their Security blob.

Usage:
    # Check what would be cleaned (safe - no changes)
    python cleanup_security_blobs.py --check

    # Actually clean the blobs
    python cleanup_security_blobs.py

    # Clean specific accounts only
    python cleanup_security_blobs.py --limit 10

Environment Variables Required:
    PLAYFAB_TITLE_ID    - Your PlayFab title ID
    PLAYFAB_SECRET_KEY  - PlayFab server secret key

Input:
    false_banned.JSON - JSON file with affected accounts (device_id -> {playFabId, metaId, reason})

Author: Generated for UG breach remediation
Date: January 2026
"""

import json
import os
import sys
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

API_DELAY = 0.2  # Seconds between API calls
MAX_RETRIES = 3
RETRY_DELAY = 2

# The fake ban reason used by the attacker
FAKE_BAN_REASON = "PlayFab ban: Racism | Bullying | Hateful Behavior"

# ============================================================================
# PLAYFAB API HELPERS
# ============================================================================

def get_security_blob(playfab_id: str, title_id: str, secret_key: str) -> dict | None:
    """Fetch the Security blob for a player."""
    url = f'https://{title_id}.playfabapi.com/Server/GetUserInternalData'
    headers = {
        'Content-Type': 'application/json',
        'X-SecretKey': secret_key
    }
    payload = {
        'PlayFabId': playfab_id,
        'Keys': ['Security']
    }
    
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        if resp.ok:
            data = resp.json()
            security_value = data.get('data', {}).get('Data', {}).get('Security', {}).get('Value')
            if security_value:
                return json.loads(security_value)
        return None
    except Exception as e:
        print(f"Error fetching blob for {playfab_id}: {e}")
        return None


def clear_security_blob(playfab_id: str, title_id: str, secret_key: str, dry_run: bool = False) -> dict:
    """Clear/delete the Security blob for a player."""
    if dry_run:
        return {'success': True, 'dry_run': True}
    
    url = f'https://{title_id}.playfabapi.com/Server/UpdateUserInternalData'
    headers = {
        'Content-Type': 'application/json',
        'X-SecretKey': secret_key
    }
    # Setting to empty object effectively clears it
    payload = {
        'PlayFabId': playfab_id,
        'Data': {'Security': '{}'}
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=10)
            if resp.ok:
                return {'success': True}
            else:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                continue
            return {'success': False, 'error': str(e)}
    
    return {'success': False, 'error': 'Max retries exceeded'}


def remove_fake_ban_from_blob(playfab_id: str, title_id: str, secret_key: str, 
                               blob: dict, dry_run: bool = False) -> dict:
    """Remove only the fake ban entry from the blob, preserving other data."""
    if dry_run:
        return {'success': True, 'dry_run': True}
    
    # Remove the mb (meta ban) section if it contains the fake reason
    if 'mb' in blob and blob['mb'].get('r') == FAKE_BAN_REASON:
        del blob['mb']
    
    # Update the blob
    url = f'https://{title_id}.playfabapi.com/Server/UpdateUserInternalData'
    headers = {
        'Content-Type': 'application/json',
        'X-SecretKey': secret_key
    }
    payload = {
        'PlayFabId': playfab_id,
        'Data': {'Security': json.dumps(blob)}
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=10)
            if resp.ok:
                return {'success': True}
            else:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                continue
            return {'success': False, 'error': str(e)}
    
    return {'success': False, 'error': 'Max retries exceeded'}


# ============================================================================
# ANALYSIS HELPERS
# ============================================================================

def analyze_blob(blob: dict) -> dict:
    """
    Analyze a Security blob to determine if it only contains fake ban data.
    
    Returns:
        {
            'is_fake_only': True if only contains fake ban,
            'has_fake_ban': True if contains the fake ban reason,
            'has_other_data': True if has other legitimate data,
            'recommendation': 'clear' | 'remove_ban' | 'skip',
            'details': {...}
        }
    """
    result = {
        'is_fake_only': False,
        'has_fake_ban': False,
        'has_other_data': False,
        'recommendation': 'skip',
        'details': {}
    }
    
    if not blob:
        result['recommendation'] = 'skip'
        result['details']['reason'] = 'No blob found'
        return result
    
    # Check for fake ban in mb (meta ban) section
    mb = blob.get('mb', {})
    if mb.get('r') == FAKE_BAN_REASON:
        result['has_fake_ban'] = True
    
    # Check for other data that indicates legitimate history
    has_other = False
    
    # di = device integrity section (may have legitimate attestation failures)
    di = blob.get('di', {})
    # Check if di has anything OTHER than what would be set by the fake ban
    di_keys_from_ban = {'linkedAlt', 'linkedTo', 'linkedAt'}  # These might be set by ban process
    other_di_keys = set(di.keys()) - di_keys_from_ban
    if other_di_keys:
        # Check if these are meaningful values
        for key in other_di_keys:
            if di.get(key):
                has_other = True
                result['details']['has_di_data'] = True
                break
    
    # Check for other top-level keys that indicate history
    other_keys = set(blob.keys()) - {'v', 'mb', 'di', 'lua'}
    if other_keys:
        has_other = True
        result['details']['other_keys'] = list(other_keys)
    
    result['has_other_data'] = has_other
    
    # Determine recommendation
    if result['has_fake_ban']:
        if not result['has_other_data']:
            result['is_fake_only'] = True
            result['recommendation'] = 'clear'
        else:
            result['recommendation'] = 'remove_ban'
    else:
        result['recommendation'] = 'skip'
        result['details']['reason'] = 'No fake ban found'
    
    return result


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Clean up Security blobs for falsely banned accounts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check what would be cleaned (safe)
  $env:PLAYFAB_TITLE_ID = "XXXXX"
  $env:PLAYFAB_SECRET_KEY = "your_key"
  python cleanup_security_blobs.py --check

  # Actually clean the blobs
  python cleanup_security_blobs.py

  # Process specific file
  python cleanup_security_blobs.py --input false_banned.JSON
        """
    )
    
    parser.add_argument('--input', '-i', default='false_banned.JSON',
                        help='JSON file with affected accounts (default: false_banned.JSON)')
    parser.add_argument('--check', '-c', action='store_true',
                        help='Check/analyze only, no changes')
    parser.add_argument('--dry-run', '-n', action='store_true',
                        help='Simulate cleanup without making changes')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Save results to JSON file')
    parser.add_argument('--limit', type=int,
                        help='Limit number of accounts to process')
    parser.add_argument('--force-clear', action='store_true',
                        help='Clear entire blob even if other data exists (use with caution)')
    
    args = parser.parse_args()
    
    # Get credentials
    title_id = os.environ.get('PLAYFAB_TITLE_ID')
    secret_key = os.environ.get('PLAYFAB_SECRET_KEY')
    
    if not title_id or not secret_key:
        print("Error: PLAYFAB_TITLE_ID and PLAYFAB_SECRET_KEY environment variables required")
        print("\nSet them with:")
        print('  PowerShell: $env:PLAYFAB_TITLE_ID = "XXXXX"')
        print('              $env:PLAYFAB_SECRET_KEY = "your_key"')
        sys.exit(1)
    
    # Load affected accounts
    if not Path(args.input).exists():
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)
    
    with open(args.input, 'r') as f:
        affected_accounts = json.load(f)
    
    print(f"Loaded {len(affected_accounts)} affected accounts from {args.input}")
    
    # Convert to list for processing
    accounts = []
    for device_id, info in affected_accounts.items():
        accounts.append({
            'device_id': device_id,
            'playfab_id': info['playFabId'],
            'meta_id': info['metaId'],
            'stored_reason': info['reason']
        })
    
    if args.limit:
        accounts = accounts[:args.limit]
        print(f"Limiting to {args.limit} accounts")
    
    # Process accounts
    results = []
    stats = {
        'total': len(accounts),
        'analyzed': 0,
        'fake_only': 0,
        'has_other_data': 0,
        'no_blob': 0,
        'no_fake_ban': 0,
        'cleared': 0,
        'cleaned': 0,
        'skipped': 0,
        'errors': 0
    }
    
    mode = "CHECK" if args.check else ("DRY RUN" if args.dry_run else "CLEANUP")
    print(f"\n{'='*70}")
    print(f"MODE: {mode}")
    print(f"{'='*70}\n")
    
    for i, account in enumerate(accounts):
        idx = i + 1
        pfid = account['playfab_id']
        
        print(f"[{idx}/{len(accounts)}] PlayFabId: {pfid}", end=' ')
        
        # Fetch blob
        blob = get_security_blob(pfid, title_id, secret_key)
        time.sleep(API_DELAY)
        
        # Analyze
        analysis = analyze_blob(blob)
        stats['analyzed'] += 1
        
        result = {
            'playfab_id': pfid,
            'meta_id': account['meta_id'],
            'device_id': account['device_id'][:16] + '...',
            'analysis': analysis,
            'action': None,
            'success': None
        }
        
        if not blob:
            stats['no_blob'] += 1
            result['action'] = 'skip_no_blob'
            print("- No blob found, skipping")
        elif not analysis['has_fake_ban']:
            stats['no_fake_ban'] += 1
            result['action'] = 'skip_no_fake'
            print("- No fake ban in blob, skipping")
        elif analysis['is_fake_only'] or args.force_clear:
            stats['fake_only'] += 1
            result['action'] = 'clear'
            
            if args.check:
                print("→ Would CLEAR (fake ban only)")
                stats['skipped'] += 1
            else:
                # Clear the entire blob
                clear_result = clear_security_blob(pfid, title_id, secret_key, args.dry_run)
                result['success'] = clear_result.get('success')
                
                if clear_result.get('success'):
                    stats['cleared'] += 1
                    print("✓ CLEARED")
                else:
                    stats['errors'] += 1
                    print(f"✗ ERROR: {clear_result.get('error')}")
                
                time.sleep(API_DELAY)
        else:
            # Has other data - remove only the fake ban
            stats['has_other_data'] += 1
            result['action'] = 'remove_ban'
            
            if args.check:
                print("→ Would REMOVE fake ban (has other data)")
                stats['skipped'] += 1
            else:
                clean_result = remove_fake_ban_from_blob(pfid, title_id, secret_key, blob, args.dry_run)
                result['success'] = clean_result.get('success')
                
                if clean_result.get('success'):
                    stats['cleaned'] += 1
                    print("✓ REMOVED fake ban")
                else:
                    stats['errors'] += 1
                    print(f"✗ ERROR: {clean_result.get('error')}")
                
                time.sleep(API_DELAY)
        
        results.append(result)
    
    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"  Total accounts:       {stats['total']}")
    print(f"  Analyzed:             {stats['analyzed']}")
    print(f"  - Fake ban only:      {stats['fake_only']}")
    print(f"  - Has other data:     {stats['has_other_data']}")
    print(f"  - No blob found:      {stats['no_blob']}")
    print(f"  - No fake ban:        {stats['no_fake_ban']}")
    
    if not args.check:
        print(f"\n  Actions taken:")
        print(f"  - Blobs cleared:      {stats['cleared']}")
        print(f"  - Fake bans removed:  {stats['cleaned']}")
        print(f"  - Errors:             {stats['errors']}")
    
    # Save results
    if args.output:
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'mode': mode,
            'stats': stats,
            'results': results
        }
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nResults saved to: {args.output}")
    
    if stats['errors'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
