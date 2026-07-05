# collector/log_collector.py
import win32evtlog
import win32api
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import LOG_SOURCE, MAX_EVENTS, LOOKBACK_HOURS, EVENT_IDS
from parser.event_parser import parse_event_xml

# High-volume events collected separately with their own cap
PROCESS_EVENT_IDS = {4688}

# Authentication and account events — lower volume, higher fidelity
AUTH_EVENT_IDS = {
    4624, 4625, 4634, 4647, 4672,
    4719, 4720, 4726, 4728, 4732,
    4740, 4756
}


def _run_query(channel: str, xpath: str, max_events: int,
               cutoff_time: datetime, label: str) -> list:
    """
    Execute a single XPath query against the Windows Event Log
    and return normalized parsed events.
    """
    events = []
    try:
        query_handle = win32evtlog.EvtQuery(
            channel,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            xpath
        )
    except Exception as e:
        print(f"[!] Failed to open query ({label}): {e}")
        return []

    collected = 0
    scanned   = 0

    try:
        while collected < max_events:
            try:
                raw_events = win32evtlog.EvtNext(query_handle, 10)
            except Exception:
                break

            if not raw_events:
                break

            for event_handle in raw_events:
                scanned += 1
                try:
                    xml_string = win32evtlog.EvtRender(
                        event_handle,
                        win32evtlog.EvtRenderEventXml
                    )
                except Exception:
                    xml_string = None
                finally:
                    try:
                        win32api.CloseHandle(event_handle)
                    except Exception:
                        pass

                if not xml_string:
                    continue

                parsed = parse_event_xml(xml_string)
                if parsed is None:
                    continue

                if parsed["timestamp"] and parsed["timestamp"] < cutoff_time:
                    print(f"[*] [{label}] Reached lookback boundary "
                          f"({scanned} scanned, {collected} collected)")
                    return events

                events.append(parsed)
                collected += 1

    except Exception as e:
        print(f"[!] Error in query ({label}): {e}")
    finally:
        try:
            win32api.CloseHandle(query_handle)
        except Exception:
            pass

    print(f"[*] [{label}] Complete: {collected} events collected")
    return events


def collect_events(
    lookback_hours: int = LOOKBACK_HOURS,
    max_events: int = MAX_EVENTS,
    target_event_ids: set = None
) -> list:
    """
    Collect security events using split queries:
    - Auth/account events: deep lookback, high priority
    - Process creation events: separate cap to prevent noise flooding
    """
    if target_event_ids is None:
        target_event_ids = set(EVENT_IDS.keys())

    cutoff_time = datetime.now() - timedelta(hours=lookback_hours)

    print(f"[*] Collecting events from Security log")
    print(f"[*] Lookback: {lookback_hours}h "
          f"(from {cutoff_time.strftime('%Y-%m-%d %H:%M:%S')})")

    all_events = []

    # ── Query 1: Authentication & account events (no cap issue) ──────────
    auth_ids = AUTH_EVENT_IDS & target_event_ids
    if auth_ids:
        id_filter = " or ".join(f"EventID={eid}" for eid in sorted(auth_ids))
        xpath = f"*[System[({id_filter})]]"
        print(f"[*] Query 1 — Auth/Account events: {sorted(auth_ids)}")
        auth_events = _run_query(
            LOG_SOURCE, xpath,
            max_events=max_events,
            cutoff_time=cutoff_time,
            label="Auth"
        )
        all_events.extend(auth_events)

    # ── Query 2: Process creation events (separate smaller cap) ──────────
    proc_ids = PROCESS_EVENT_IDS & target_event_ids
    if proc_ids:
        id_filter = " or ".join(f"EventID={eid}" for eid in sorted(proc_ids))
        xpath = f"*[System[({id_filter})]]"
        # Cap process events at 2000 to prevent noise flooding
        proc_cap = min(2000, max_events)
        print(f"[*] Query 2 — Process events (cap: {proc_cap}): {sorted(proc_ids)}")
        proc_events = _run_query(
            LOG_SOURCE, xpath,
            max_events=proc_cap,
            cutoff_time=cutoff_time,
            label="Process"
        )
        all_events.extend(proc_events)

    # Sort combined results by timestamp descending
    all_events.sort(
        key=lambda e: e["timestamp"] or datetime.min,
        reverse=True
    )

    print(f"[+] Total collected: {len(all_events)} events")
    return all_events


if __name__ == "__main__":
    events = collect_events(lookback_hours=72, max_events=5000)
    print(f"\nSample of collected events:")
    for e in events[:10]:
        user = e["target_user"] or e["subject_user"]
        print(f"  [{e['timestamp']}] ID:{e['event_id']} "
              f"({e['event_name']}) user:{user}")

    from collections import Counter
    dist = Counter(e["event_id"] for e in events)
    print(f"\nEvent ID distribution:")
    for eid, count in sorted(dist.items()):
        print(f"  {eid} ({EVENT_IDS.get(eid, 'Unknown')}): {count}")
