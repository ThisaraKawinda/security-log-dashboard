# run_pipeline.py
"""
Pipeline runner: collects events from Windows Security log
and stores them in SQLite. Run this as Administrator.
"""
import sys
import os
sys.path.append('.')

from storage.database import initialize_database, insert_events, get_database_stats
from collector.log_collector import collect_events


def run(lookback_hours: int = 72, max_events: int = 5000):
    print("=" * 55)
    print("  Security Log Analysis Dashboard — Pipeline Runner")
    print("=" * 55)

    # Step 1: Initialize database
    print("\n[1/3] Initializing database...")
    initialize_database()

    # Step 2: Collect events
    print("\n[2/3] Collecting events from Windows Security log...")
    events = collect_events(lookback_hours=lookback_hours, max_events=max_events)
    print(f"      Collected {len(events)} events")

    # Step 3: Store events
    print("\n[3/3] Storing events in SQLite...")
    result = insert_events(events)
    print(f"      Inserted : {result['inserted']}")
    print(f"      Skipped  : {result['skipped']} (duplicates)")

    # Summary
    print("\n" + "=" * 55)
    print("  Database Summary")
    print("=" * 55)
    stats = get_database_stats()
    print(f"  Total events : {stats['total_events']}")
    print(f"  Oldest event : {stats['oldest_event']}")
    print(f"  Newest event : {stats['newest_event']}")
    print(f"\n  Breakdown by Event ID:")
    for row in stats['by_event_id']:
        print(f"    {row['event_id']} ({row['event_name']}): {row['count']}")
    print("=" * 55)
    print("  Pipeline complete.")
    print("=" * 55)


if __name__ == "__main__":
    run()
