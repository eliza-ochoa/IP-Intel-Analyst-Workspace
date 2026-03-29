from __future__ import annotations

import json
from datetime import datetime

import pandas as pd
import streamlit as st

from ip_intel.service import IPIntelligenceService
from ip_intel.storage import InvestigationStorage

st.set_page_config(
    page_title="IP Intelligence Analyst Workspace",
    page_icon="🌐",
    layout="wide",
)

ANALYST_TAGS = ["benign", "needs_review", "suspicious", "malicious"]


@st.cache_resource
def get_service() -> IPIntelligenceService:
    return IPIntelligenceService()


@st.cache_resource
def get_storage() -> InvestigationStorage:
    return InvestigationStorage()


def risk_label(score: int) -> tuple[str, str]:
    if score < 20:
        return "LOW", "green"
    if score < 40:
        return "MEDIUM", "orange"
    return "HIGH", "red"


def normalize_results(results: list[dict]) -> pd.DataFrame:
    cleaned_rows = []

    for row in results:
        row_copy = row.copy()

        if isinstance(row_copy.get("privacy"), dict):
            row_copy["privacy"] = json.dumps(row_copy["privacy"])

        if isinstance(row_copy.get("risk_flags"), list):
            row_copy["risk_flags"] = ", ".join(row_copy["risk_flags"])

        cleaned_rows.append(row_copy)

    df = pd.DataFrame(cleaned_rows)

    preferred_columns = [
        "ip",
        "source",
        "ip_type",
        "risk_score",
        "risk_flags",
        "country",
        "region",
        "city",
        "postal",
        "timezone",
        "org",
        "asn",
        "hostname",
        "latitude",
        "longitude",
        "privacy",
        "error",
    ]

    existing = [col for col in preferred_columns if col in df.columns]
    return df[existing] if existing else df


def save_investigation_record(
    storage: InvestigationStorage,
    data: dict,
    tag: str,
    notes: str,
) -> None:
    record = {
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": data.get("ip", ""),
        "source": data.get("source", ""),
        "ip_type": data.get("ip_type", ""),
        "risk_score": data.get("risk_score", 0),
        "risk_flags": ", ".join(data.get("risk_flags", []))
        if isinstance(data.get("risk_flags"), list)
        else str(data.get("risk_flags", "")),
        "country": data.get("country", ""),
        "region": data.get("region", ""),
        "city": data.get("city", ""),
        "org": data.get("org", ""),
        "asn": data.get("asn", ""),
        "hostname": data.get("hostname", ""),
        "tag": tag,
        "notes": notes,
        "error": data.get("error", ""),
    }
    storage.save_record(record)


def analyst_sidebar_filters(df: pd.DataFrame) -> pd.DataFrame:
    st.sidebar.header("Workspace Filters")
    filtered = df.copy()

    if filtered.empty:
        return filtered

    if "tag" in filtered.columns:
        tag_values = sorted([x for x in filtered["tag"].dropna().astype(str).unique().tolist() if x])
        selected_tags = st.sidebar.multiselect("Tag", tag_values)
        if selected_tags:
            filtered = filtered[filtered["tag"].isin(selected_tags)]

    if "country" in filtered.columns:
        country_values = sorted([x for x in filtered["country"].dropna().astype(str).unique().tolist() if x])
        selected_countries = st.sidebar.multiselect("Country", country_values)
        if selected_countries:
            filtered = filtered[filtered["country"].isin(selected_countries)]

    if "source" in filtered.columns:
        source_values = sorted([x for x in filtered["source"].dropna().astype(str).unique().tolist() if x])
        selected_sources = st.sidebar.multiselect("Source", source_values)
        if selected_sources:
            filtered = filtered[filtered["source"].isin(selected_sources)]

    if "ip_type" in filtered.columns:
        ip_types = sorted([x for x in filtered["ip_type"].dropna().astype(str).unique().tolist() if x])
        selected_ip_types = st.sidebar.multiselect("IP Type", ip_types)
        if selected_ip_types:
            filtered = filtered[filtered["ip_type"].isin(selected_ip_types)]

    if "risk_score" in filtered.columns:
        numeric_scores = pd.to_numeric(filtered["risk_score"], errors="coerce").fillna(0).astype(int)
        min_score = int(numeric_scores.min())
        max_score = int(numeric_scores.max())
        selected_range = st.sidebar.slider(
            "Risk Score Range",
            min_value=min_score,
            max_value=max_score if max_score >= min_score else min_score,
            value=(min_score, max_score if max_score >= min_score else min_score),
        )
        filtered = filtered[numeric_scores.between(selected_range[0], selected_range[1])]

    notes_only = st.sidebar.checkbox("Show only rows with notes")
    if notes_only and "notes" in filtered.columns:
        filtered = filtered[filtered["notes"].fillna("").astype(str).str.strip() != ""]

    return filtered


def render_single_lookup(service: IPIntelligenceService, storage: InvestigationStorage) -> None:
    st.subheader("Single IP Investigation")

    ip = st.text_input("Enter an IP address", placeholder="8.8.8.8", key="single_ip_input")

    if st.button("Analyze IP", key="analyze_single_ip"):
        if not ip.strip():
            st.warning("Please enter an IP address.")
            return

        try:
            result = service.lookup(ip.strip())
            st.session_state["single_result"] = service.as_dict(result)
        except Exception as exc:
            st.error(f"Lookup failed: {exc}")
            return

    data = st.session_state.get("single_result")
    if not data:
        st.info("Run a single IP analysis to view analyst details.")
        return

    score = int(data.get("risk_score", 0))
    label, color = risk_label(score)

    top1, top2, top3, top4 = st.columns(4)
    top1.metric("Country", data.get("country") or "N/A")
    top2.metric("Organization", data.get("org") or "N/A")
    top3.metric("ASN", data.get("asn") or "N/A")
    top4.metric("IP Type", data.get("ip_type") or "N/A")

    st.markdown(f"### Risk Assessment: :{color}[{label}] ({score}/100)")
    st.progress(score / 100)

    left, right = st.columns([2, 1])

    with left:
        st.write("### Investigation Details")
        detail_rows = [
            ("IP", data.get("ip")),
            ("Source", data.get("source")),
            ("Country", data.get("country")),
            ("Region", data.get("region")),
            ("City", data.get("city")),
            ("Organization", data.get("org")),
            ("ASN", data.get("asn")),
            ("Hostname", data.get("hostname")),
            ("Error", data.get("error")),
        ]
        detail_df = pd.DataFrame(detail_rows, columns=["Field", "Value"])
        st.dataframe(detail_df, use_container_width=True, hide_index=True)

        st.write("### Risk Indicators")
        flags = data.get("risk_flags", [])
        if flags:
            for flag in flags:
                st.write(f"⚠️ {flag}")
        else:
            st.write("No significant risk indicators detected.")

        st.write("### Analyst Verdict")
        if score < 20:
            st.success("Likely normal / benign IP")
        elif score < 40:
            st.warning("Potentially suspicious — review recommended")
        else:
            st.error("High-risk indicators — investigate further")

    with right:
        st.write("### Analyst Review")
        default_tag = "needs_review"
        previous = storage.latest_record_for_ip(data.get("ip", ""))
        if previous and previous.get("tag") in ANALYST_TAGS:
            default_tag = previous["tag"]

        tag = st.selectbox(
            "Analyst Tag",
            ANALYST_TAGS,
            index=ANALYST_TAGS.index(default_tag),
            key="single_tag",
        )

        default_notes = previous.get("notes", "") if previous else ""
        notes = st.text_area(
            "Analyst Notes",
            value=default_notes,
            height=180,
            key="single_notes",
        )

        if st.button("Save Investigation", key="save_single_investigation"):
            save_investigation_record(storage, data, tag, notes)
            st.success("Investigation saved to workspace history.")

    lat = data.get("latitude")
    lon = data.get("longitude")
    if lat is not None and lon is not None:
        st.write("### Geolocation")
        map_df = pd.DataFrame([{"latitude": lat, "longitude": lon}])
        st.map(map_df)

    with st.expander("Show full raw data"):
        st.json(data)


def render_batch_workspace(service: IPIntelligenceService, storage: InvestigationStorage) -> None:
    st.subheader("Batch Investigation Workspace")

    uploaded_file = st.file_uploader(
        "Upload a CSV file with a column named 'ip'",
        type=["csv"],
        key="batch_uploader",
    )

    if uploaded_file is None:
        st.info("Upload a CSV file to begin batch investigation.")
        return

    try:
        input_df = pd.read_csv(uploaded_file)
    except Exception as exc:
        st.error(f"Could not read CSV file: {exc}")
        return

    st.write("### Uploaded File Preview")
    st.dataframe(input_df, use_container_width=True)

    if "ip" not in input_df.columns:
        st.error("CSV must contain a column named 'ip'.")
        return

    if st.button("Run Batch Investigation", key="run_batch_investigation"):
        results = []
        progress = st.progress(0)
        status = st.empty()

        ips = [str(ip).strip() for ip in input_df["ip"].dropna().tolist() if str(ip).strip()]

        if not ips:
            st.warning("No valid IP values found in the uploaded CSV.")
            return

        for idx, ip in enumerate(ips, start=1):
            status.text(f"Processing {idx} of {len(ips)}: {ip}")
            result = service.lookup(ip)
            results.append(service.as_dict(result))
            progress.progress(idx / len(ips))

        status.text("Batch investigation complete.")
        st.session_state["batch_results_df"] = normalize_results(results)

    if "batch_results_df" not in st.session_state:
        return

    results_df = st.session_state["batch_results_df"]

    st.write("### Batch Summary")
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Rows", str(len(results_df)))
    s2.metric(
        "High Risk",
        str(len(results_df[pd.to_numeric(results_df["risk_score"], errors="coerce").fillna(0) >= 40]))
        if "risk_score" in results_df.columns
        else "0",
    )
    s3.metric(
        "Errors",
        str(len(results_df[results_df["error"].fillna("").astype(str).str.strip() != ""]))
        if "error" in results_df.columns
        else "0",
    )
    s4.metric(
        "Public IPs",
        str(len(results_df[results_df["ip_type"] == "public"]))
        if "ip_type" in results_df.columns
        else "0",
    )

    st.write("### Results")
    st.dataframe(results_df, use_container_width=True)

    csv_data = results_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download Batch Results CSV",
        data=csv_data,
        file_name="batch_investigation_results.csv",
        mime="text/csv",
        key="download_batch_results",
    )

    st.write("### Analyst Bulk Save")

    save_option = st.selectbox(
        "Select rows to save",
        ["All Results", "High Risk Only"],
        key="batch_save_option",
    )

    bulk_tag = st.selectbox(
        "Select Tag",
        ANALYST_TAGS,
        index=ANALYST_TAGS.index("needs_review"),
        key="batch_tag",
    )

    bulk_notes = st.text_area(
        "Notes (applied to all saved rows)",
        key="batch_notes",
        height=140,
    )

    if st.button("Save Batch to Investigation Workspace", key="save_batch"):
        df_to_save = results_df.copy()

        if save_option == "High Risk Only" and "risk_score" in df_to_save.columns:
            df_to_save = df_to_save[pd.to_numeric(df_to_save["risk_score"], errors="coerce").fillna(0) >= 40]

        if df_to_save.empty:
            st.warning("No rows to save.")
        else:
            saved_count = 0
            for _, row in df_to_save.iterrows():
                record = {
                    "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": row.get("ip", ""),
                    "source": row.get("source", ""),
                    "ip_type": row.get("ip_type", ""),
                    "risk_score": row.get("risk_score", 0),
                    "risk_flags": row.get("risk_flags", ""),
                    "country": row.get("country", ""),
                    "region": row.get("region", ""),
                    "city": row.get("city", ""),
                    "org": row.get("org", ""),
                    "asn": row.get("asn", ""),
                    "hostname": row.get("hostname", ""),
                    "tag": bulk_tag,
                    "notes": bulk_notes,
                    "error": row.get("error", ""),
                }
                storage.save_record(record)
                saved_count += 1

            st.success(f"Saved {saved_count} records to investigation workspace.")

    if {"latitude", "longitude"}.issubset(results_df.columns):
        map_df = results_df[["latitude", "longitude"]].dropna()
        if not map_df.empty:
            st.write("### Geolocation Map")
            st.map(map_df)

    c1, c2 = st.columns(2)

    with c1:
        st.write("### Risk Distribution")
        if "risk_score" in results_df.columns and not results_df.empty:
            risk_counts = (
                pd.to_numeric(results_df["risk_score"], errors="coerce")
                .fillna(0)
                .astype(int)
                .apply(lambda x: "0-19" if x < 20 else "20-39" if x < 40 else "40-59" if x < 60 else "60+")
                .value_counts()
                .rename_axis("Bucket")
                .reset_index(name="Count")
            )
            st.dataframe(risk_counts, use_container_width=True)
            st.bar_chart(risk_counts.set_index("Bucket"))

    with c2:
        st.write("### IP Type Distribution")
        if "ip_type" in results_df.columns and not results_df.empty:
            ip_type_counts = (
                results_df["ip_type"]
                .fillna("unknown")
                .value_counts()
                .rename_axis("IP Type")
                .reset_index(name="Count")
            )
            st.dataframe(ip_type_counts, use_container_width=True)
            st.bar_chart(ip_type_counts.set_index("IP Type"))


def render_saved_workspace(storage: InvestigationStorage) -> None:
    st.subheader("Saved Investigation Workspace")

    saved_df = storage.load()

    if saved_df.empty:
        st.info("No investigations saved yet.")
        return

    filtered_df = analyst_sidebar_filters(saved_df)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Saved Records", str(len(filtered_df)))
    m2.metric("Malicious", str(len(filtered_df[filtered_df["tag"] == "malicious"])) if "tag" in filtered_df.columns else "0")
    m3.metric("Suspicious", str(len(filtered_df[filtered_df["tag"] == "suspicious"])) if "tag" in filtered_df.columns else "0")
    m4.metric("Needs Review", str(len(filtered_df[filtered_df["tag"] == "needs_review"])) if "tag" in filtered_df.columns else "0")

    st.write("### Analyst Case History")
    st.dataframe(filtered_df, use_container_width=True)

    export_csv = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download Investigation History",
        data=export_csv,
        file_name="investigation_history.csv",
        mime="text/csv",
        key="download_investigation_history",
    )

    with st.expander("Quick Search by IP"):
        search_ip = st.text_input("Enter IP to search saved history", key="search_saved_ip")
        if search_ip.strip():
            ip_filtered = saved_df[saved_df["ip"].astype(str) == search_ip.strip()]
            if not ip_filtered.empty:
                st.dataframe(ip_filtered, use_container_width=True)
            else:
                st.info("No saved records found for that IP.")


def main() -> None:
    st.title("🌐 IP Intelligence Analyst Workspace")
    st.image("assets/banner.png", use_container_width=True)
    st.caption("Investigate, classify, tag, document, and save IP intelligence cases.")

    service = get_service()
    storage = get_storage()

    tab1, tab2, tab3 = st.tabs(
        ["Single Investigation", "Batch Investigation", "Saved Workspace"]
    )

    with tab1:
        render_single_lookup(service, storage)

    with tab2:
        render_batch_workspace(service, storage)

    with tab3:
        render_saved_workspace(storage)


if __name__ == "__main__":
    main()

    