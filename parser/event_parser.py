# parser/event_parser.py
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import LOGON_TYPES, SUBSTATUS_CODES, EVENT_IDS

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_event_xml(xml_string: str) -> Optional[dict]:
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return None

    system = root.find("e:System", NS)
    if system is None:
        return None

    event_id_el = system.find("e:EventID", NS)
    time_el     = system.find("e:TimeCreated", NS)
    computer_el = system.find("e:Computer", NS)

    if any(el is None for el in [event_id_el, time_el, computer_el]):
        return None

    event_id = int(event_id_el.text)
    raw_time = time_el.get("SystemTime", "")
    computer = computer_el.text

    try:
        timestamp = datetime.strptime(raw_time[:26], "%Y-%m-%dT%H:%M:%S.%f")
    except (ValueError, IndexError):
        timestamp = None

    record = {
        "event_id":        event_id,
        "event_name":      EVENT_IDS.get(event_id, f"Unknown ({event_id})"),
        "timestamp":       timestamp,
        "hour_of_day":     timestamp.hour if timestamp else None,
        "day_of_week":     timestamp.strftime("%A") if timestamp else None,
        "computer":        computer,
        "subject_user":    None,
        "target_user":     None,
        "logon_type":      None,
        "logon_type_desc": None,
        "failure_reason":  None,
        "substatus":       None,
        "substatus_desc":  None,
        "source_ip":       None,
        "process_name":    None,
        "command_line":    None,
        "group_name":      None,
        "raw_xml":         xml_string,
    }

    event_data = root.find("e:EventData", NS)
    data_map   = {}
    if event_data is not None:
        for data_el in event_data.findall("e:Data", NS):
            name  = data_el.get("Name")
            value = data_el.text or ""
            if name:
                data_map[name] = value

    if event_id in (4624, 4625):
        record = _enrich_logon_event(record, data_map)
    elif event_id in (4720, 4726):
        record = _enrich_account_event(record, data_map)
    elif event_id in (4728, 4732, 4756):
        record = _enrich_group_event(record, data_map)
    elif event_id == 4688:
        record = _enrich_process_event(record, data_map)
    elif event_id == 4740:
        record = _enrich_lockout_event(record, data_map)
    elif event_id == 4672:
        record = _enrich_special_logon_event(record, data_map)

    return record


def _enrich_logon_event(record: dict, data: dict) -> dict:
    logon_type_raw = data.get("LogonType", "")
    try:
        logon_type_int = int(logon_type_raw)
    except ValueError:
        logon_type_int = None

    substatus_raw = data.get("SubStatus", "").lower()

    record.update({
        "subject_user":    data.get("SubjectUserName"),
        "target_user":     data.get("TargetUserName"),
        "logon_type":      logon_type_int,
        "logon_type_desc": LOGON_TYPES.get(logon_type_int, f"Unknown ({logon_type_raw})"),
        "failure_reason":  data.get("FailureReason"),
        "substatus":       substatus_raw,
        "substatus_desc":  SUBSTATUS_CODES.get(substatus_raw, substatus_raw),
        "source_ip":       data.get("IpAddress"),
    })
    return record


def _enrich_account_event(record: dict, data: dict) -> dict:
    record.update({
        "subject_user": data.get("SubjectUserName"),
        "target_user":  data.get("TargetUserName"),
    })
    return record


def _enrich_group_event(record: dict, data: dict) -> dict:
    record.update({
        "subject_user": data.get("SubjectUserName"),
        "target_user":  data.get("MemberName") or data.get("MemberSid"),
        "group_name":   data.get("GroupName"),
    })
    return record


def _enrich_process_event(record: dict, data: dict) -> dict:
    record.update({
        "subject_user": data.get("SubjectUserName"),
        "process_name": data.get("NewProcessName"),
        "command_line": data.get("CommandLine"),
    })
    return record


def _enrich_lockout_event(record: dict, data: dict) -> dict:
    record.update({
        "target_user": data.get("TargetUserName"),
        "source_ip":   data.get("CallerComputerName"),
    })
    return record


def _enrich_special_logon_event(record: dict, data: dict) -> dict:
    record.update({
        "subject_user": data.get("SubjectUserName"),
    })
    return record
