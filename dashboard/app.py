# dashboard/app.py
"""
Security Log Analysis Dashboard
Streamlit-based interactive dashboard for Windows Security Event Log monitoring.
Run as: streamlit run dashboard/app.py
Must be run from the project root directory.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import sqlite3
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DB_PATH, EVENT_IDS
from detection.rules import run_all_rules

# ── Page configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Security Log Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background-color: #1e1e2e;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .severity-critical { color: #ff4444; font-weight: bold; }
    .severity-high     { color: #ff8800; font-weight: bold; }
    .severity-medium   { color: #ffcc00; font-weight: bold; }
    .severity-low      { color: #44aaff; font-weight: bold; }
    .alert-box {
        border-left: 4px solid #ff4444;
        padding: 8px 12px;
        margin: 4px 0;
        background-color: #1a1a2e;
        border-radius: 0 4px 4px 0;
    }
    .alert-box-high   { border-left-color: #ff8800; }
    .alert-box-medium { border-left-color: #ffcc00; }
    .alert-box-low    { border-left-color: #44aaff; }
</style>
""", unsafe_allow_html=True)


# ── Data loading functions ────────────────────────────────────────────────────
@st.cache_data(ttl=60)
def load_events(hours_back: int = 72) -> pd.DataFrame:
    """Load events from SQLite into a DataFrame. Cached for 60 seconds."""
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    query = f"""
        SELECT * FROM events
        WHERE timestamp >= datetime('now', '-{hours_back} hours')
        ORDER BY timestamp DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


@st.cache_data(ttl=60)
def load_all_events_for_detection() -> list:
    """Load all events as dicts for detection engine."""
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_db_stats() -> dict:
    """Get total event count and date range from database."""
    if not os.path.exists(DB_PATH):
        return {"total": 0, "oldest": None, "newest": None}
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT COUNT(*) as total,
               MIN(timestamp) as oldest,
               MAX(timestamp) as newest
        FROM events
    """).fetchone()
    conn.close()
    return {"total": row[0], "oldest": row[1], "newest": row[2]}


# ── Severity helpers ──────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
    "INFO":     "#aaaaaa",
}

SEVERITY_BG = {
    "CRITICAL": "#3d0000",
    "HIGH":     "#3d1f00",
    "MEDIUM":   "#3d3300",
    "LOW":      "#00213d",
    "INFO":     "#1a1a1a",
}


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#aaaaaa")
    return f'<span style="color:{color};font-weight:bold">[{severity}]</span>'


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("# 🛡️")
    st.title("SOC Dashboard")
    st.markdown("---")

    hours_back = st.selectbox(
        "Time Window",
        options=[24, 48, 72, 168],
        format_func=lambda x: f"Last {x}h" if x < 168 else "Last 7 days",
        index=2,
    )

    st.markdown("---")
    st.markdown("**Quick Filters**")
    show_critical = st.checkbox("CRITICAL", value=True)
    show_high     = st.checkbox("HIGH", value=True)
    show_medium   = st.checkbox("MEDIUM", value=True)
    show_low      = st.checkbox("LOW", value=True)

    st.markdown("---")
    if st.button("🔄 Run Pipeline", use_container_width=True):
        with st.spinner("Collecting fresh events..."):
            try:
                from collector.log_collector import collect_events
                from storage.database import initialize_database, insert_events
                initialize_database()
                events = collect_events(lookback_hours=hours_back)
                result = insert_events(events)
                st.success(f"Inserted {result['inserted']} new events")
                st.cache_data.clear()
            except Exception as e:
                st.error(f"Pipeline error: {e}")

    st.markdown("---")
    st.caption("Security Log Analysis Dashboard")
    st.caption("Portfolio Project — Thisara Kawinda")


# ── Load data ─────────────────────────────────────────────────────────────────
df      = load_events(hours_back)
db_stats = get_db_stats()

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ Security Log Analysis Dashboard")
col_info1, col_info2, col_info3 = st.columns(3)
with col_info1:
    st.caption(f"📅 Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
with col_info2:
    st.caption(f"🗄️ Total events in DB: {db_stats['total']:,}")
with col_info3:
    newest = db_stats.get("newest", "N/A")
    st.caption(f"🕐 Latest event: {str(newest)[:19] if newest else 'N/A'}")

st.markdown("---")

# ── Run detection engine ──────────────────────────────────────────────────────
all_events = load_all_events_for_detection()
all_alerts = run_all_rules(all_events) if all_events else []

# Apply severity filters
severity_filter = []
if show_critical: severity_filter.append("CRITICAL")
if show_high:     severity_filter.append("HIGH")
if show_medium:   severity_filter.append("MEDIUM")
if show_low:      severity_filter.append("LOW")

filtered_alerts = [a for a in all_alerts if a["severity"] in severity_filter]

# ── Alert severity summary cards ──────────────────────────────────────────────
st.subheader("Alert Summary")
c1, c2, c3, c4 = st.columns(4)

def count_by_severity(alerts, sev):
    return len([a for a in alerts if a["severity"] == sev])

with c1:
    n = count_by_severity(all_alerts, "CRITICAL")
    st.metric("🔴 CRITICAL", n, delta=None)
with c2:
    n = count_by_severity(all_alerts, "HIGH")
    st.metric("🟠 HIGH", n, delta=None)
with c3:
    n = count_by_severity(all_alerts, "MEDIUM")
    st.metric("🟡 MEDIUM", n, delta=None)
with c4:
    n = count_by_severity(all_alerts, "LOW")
    st.metric("🔵 LOW", n, delta=None)

st.markdown("---")

# ── Main content: two columns ─────────────────────────────────────────────────
left_col, right_col = st.columns([1, 1])

# ── Left: Event overview chart ────────────────────────────────────────────────
with left_col:
    st.subheader("Event Overview")
    if not df.empty:
        event_counts = (
            df.groupby(["event_id", "event_name"])
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=True)
        )
        event_counts["label"] = event_counts.apply(
            lambda r: f"{r['event_id']} - {r['event_name']}", axis=1
        )
        fig_bar = px.bar(
            event_counts,
            x="count",
            y="label",
            orientation="h",
            color="count",
            color_continuous_scale="Blues",
            labels={"count": "Event Count", "label": "Event Type"},
        )
        fig_bar.update_layout(
            plot_bgcolor="#0e1117",
            paper_bgcolor="#0e1117",
            font_color="#fafafa",
            showlegend=False,
            coloraxis_showscale=False,
            margin=dict(l=0, r=0, t=10, b=0),
            height=350,
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No events in the selected time window.")

# ── Right: Login trend chart ──────────────────────────────────────────────────
with right_col:
    st.subheader("Login Trend")
    if not df.empty:
        login_df = df[df["event_id"].isin([4624, 4625])].copy()
        if not login_df.empty:
            login_df["hour"] = login_df["timestamp"].dt.floor("h")
            login_df["type"] = login_df["event_id"].map({
                4624: "Success", 4625: "Failure"
            })
            trend = (
                login_df.groupby(["hour", "type"])
                .size()
                .reset_index(name="count")
            )
            fig_line = px.line(
                trend,
                x="hour",
                y="count",
                color="type",
                color_discrete_map={"Success": "#44aaff", "Failure": "#ff4444"},
                labels={"hour": "Time", "count": "Events", "type": ""},
            )
            fig_line.update_layout(
                plot_bgcolor="#0e1117",
                paper_bgcolor="#0e1117",
                font_color="#fafafa",
                margin=dict(l=0, r=0, t=10, b=0),
                height=350,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
            )
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("No login events in the selected time window.")
    else:
        st.info("No events in the selected time window.")

st.markdown("---")

# ── Active alerts panel ───────────────────────────────────────────────────────
st.subheader(f"Active Alerts ({len(filtered_alerts)} total)")

if not filtered_alerts:
    st.success("No alerts matching current filters.")
else:
    for alert in filtered_alerts[:20]:
        sev      = alert["severity"]
        color    = SEVERITY_COLORS.get(sev, "#aaaaaa")
        bg_color = SEVERITY_BG.get(sev, "#1a1a1a")
        st.markdown(
            f"""
            <div style="border-left: 4px solid {color};
                        padding: 10px 14px;
                        margin: 6px 0;
                        background-color: {bg_color};
                        border-radius: 0 6px 6px 0;">
                <span style="color:{color};font-weight:bold">{sev}</span>
                &nbsp;|&nbsp;
                <span style="color:#aaaaaa;font-size:0.85em">{alert['rule_id']}</span>
                &nbsp;|&nbsp;
                <strong>{alert['title']}</strong><br>
                <span style="color:#cccccc;font-size:0.9em">{alert['description']}</span><br>
                <span style="color:#888888;font-size:0.8em">
                    Fired: {alert['fired_at'][:19]} &nbsp;|&nbsp;
                    Evidence events: {alert['count']}
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("---")

# ── Event log table ───────────────────────────────────────────────────────────
st.subheader("Event Log")

if not df.empty:
    col_search, col_filter_id, col_filter_user = st.columns([2, 1, 1])

    with col_search:
        search_term = st.text_input("Search", placeholder="Search by user, IP, process...")
    with col_filter_id:
        event_id_options = ["All"] + sorted(df["event_id"].unique().tolist())
        selected_event_id = st.selectbox("Event ID", event_id_options)
    with col_filter_user:
        user_options = ["All"] + sorted(
            df["target_user"].dropna().unique().tolist()
        )
        selected_user = st.selectbox("User", user_options)

    # Apply filters
    display_df = df.copy()
    if selected_event_id != "All":
        display_df = display_df[display_df["event_id"] == selected_event_id]
    if selected_user != "All":
        display_df = display_df[
            (display_df["target_user"] == selected_user) |
            (display_df["subject_user"] == selected_user)
        ]
    if search_term:
        mask = (
            display_df["target_user"].fillna("").str.contains(search_term, case=False) |
            display_df["subject_user"].fillna("").str.contains(search_term, case=False) |
            display_df["source_ip"].fillna("").str.contains(search_term, case=False) |
            display_df["process_name"].fillna("").str.contains(search_term, case=False) |
            display_df["command_line"].fillna("").str.contains(search_term, case=False)
        )
        display_df = display_df[mask]

    # Select and rename columns for display
    display_cols = {
        "timestamp":       "Timestamp",
        "event_id":        "Event ID",
        "event_name":      "Event Name",
        "target_user":     "Target User",
        "subject_user":    "Subject User",
        "logon_type_desc": "Logon Type",
        "source_ip":       "Source IP",
        "process_name":    "Process",
        "substatus_desc":  "Failure Reason",
    }

    table_df = display_df[list(display_cols.keys())].rename(columns=display_cols)
    table_df["Timestamp"] = table_df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    table_df["Process"] = table_df["Process"].apply(
        lambda x: os.path.basename(str(x)) if pd.notna(x) else ""
    )

    st.dataframe(
        table_df.head(500),
        use_container_width=True,
        height=400,
    )
    st.caption(f"Showing {min(len(display_df), 500)} of {len(display_df)} events")
else:
    st.info("No events found. Run the pipeline first.")

# ── User activity section ─────────────────────────────────────────────────────
st.markdown("---")
st.subheader("User Activity Summary")

if not df.empty:
    ua_col1, ua_col2 = st.columns(2)

    with ua_col1:
        st.markdown("**Top Users by Event Count**")
        user_activity = (
            df["target_user"]
            .dropna()
            .value_counts()
            .head(10)
            .reset_index()
        )
        user_activity.columns = ["User", "Events"]
        fig_users = px.bar(
            user_activity,
            x="Events",
            y="User",
            orientation="h",
            color="Events",
            color_continuous_scale="Oranges",
        )
        fig_users.update_layout(
            plot_bgcolor="#0e1117",
            paper_bgcolor="#0e1117",
            font_color="#fafafa",
            showlegend=False,
            coloraxis_showscale=False,
            margin=dict(l=0, r=0, t=10, b=0),
            height=300,
        )
        st.plotly_chart(fig_users, use_container_width=True)

    with ua_col2:
        st.markdown("**Failed Logon Summary**")
        failed_df = df[df["event_id"] == 4625].copy()
        if not failed_df.empty:
            failed_summary = (
                failed_df.groupby(["target_user", "substatus_desc"])
                .size()
                .reset_index(name="Attempts")
                .sort_values("Attempts", ascending=False)
                .head(10)
            )
            failed_summary.columns = ["User", "Failure Reason", "Attempts"]
            st.dataframe(failed_summary, use_container_width=True, height=300)
        else:
            st.info("No failed logon events in the selected time window.")

# ── Logon hour heatmap ────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("Logon Activity by Hour")

if not df.empty:
    logon_df = df[df["event_id"] == 4624].copy()
    if not logon_df.empty:
        logon_df["hour"]    = logon_df["timestamp"].dt.hour
        logon_df["weekday"] = logon_df["timestamp"].dt.strftime("%A")

        weekday_order = [
            "Monday", "Tuesday", "Wednesday",
            "Thursday", "Friday", "Saturday", "Sunday"
        ]
        heatmap_data = (
            logon_df.groupby(["weekday", "hour"])
            .size()
            .reset_index(name="count")
        )
        heatmap_pivot = heatmap_data.pivot(
            index="weekday", columns="hour", values="count"
        ).reindex(weekday_order).fillna(0)

        fig_heat = px.imshow(
            heatmap_pivot,
            color_continuous_scale="Blues",
            labels=dict(x="Hour of Day", y="Day of Week", color="Logons"),
            aspect="auto",
        )
        fig_heat.update_layout(
            plot_bgcolor="#0e1117",
            paper_bgcolor="#0e1117",
            font_color="#fafafa",
            margin=dict(l=0, r=0, t=10, b=0),
            height=280,
        )
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("No logon events available for heatmap.")
