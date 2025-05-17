import streamlit as st
import requests
import pandas as pd
import plotly.express as px

# Configurable backend URL
BACKEND_URL = "http://127.0.0.1:5000/check_url"

# Page config
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded"
)

st.title("🛡️ Phishing URL Detector")
st.markdown("""
Enter one or more URLs below (one per line) to check if they are potentially malicious or safe using ML, heuristics, and Google's Safe Browsing API.
""")

# Custom CSS
st.markdown("""
<style>
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        font-weight: bold;
        height: 3em;
        width: 100%;
        border-radius: 10px;
        border: none;
        font-size: 16px;
        transition: background-color 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #45a049;
        cursor: pointer;
    }
    .url-input {
        padding: 0.5em;
        border-radius: 10px;
        border: 2px solid #4CAF50;
        font-size: 18px;
        width: 100%;
        min-height: 120px;
    }
    .result-box {
        border-radius: 10px;
        padding: 1em;
        margin-top: 1em;
        font-size: 18px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# Input multiple URLs
urls_text = st.text_area(
    "Enter URLs to check (one URL per line):",
    placeholder="https://example.com\nhttps://test.com",
    key="urls_input",
    height=120
)

check_button = st.button("🔍 Check URLs Safety")

if check_button:
    if not urls_text.strip():
        st.warning("⚠️ Please enter at least one URL to check.")
    else:
        urls = [u.strip() for u in urls_text.strip().splitlines() if u.strip()]
        st.info(f"Checking {len(urls)} URL(s)...")

        results = []
        threat_type_list = []

        progress_bar = st.progress(0)

        # Disable button and show spinner while checking
        with st.spinner("Checking URLs..."):
            for i, url in enumerate(urls, 1):
                try:
                    response = requests.post(BACKEND_URL, json={"url": url}, timeout=15)

                    # Check if response is JSON (safe parse)
                    if "application/json" in response.headers.get("Content-Type", ""):
                        data = response.json()
                    else:
                        data = {}

                    if response.status_code != 200 or "error" in data:
                        results.append({
                            "URL": url,
                            "Safe": "Error",
                            "Threat Types": data.get("error", "Unknown error"),
                            "Message": data.get("message", ""),
                        })
                    else:
                        is_safe = data.get("is_safe")
                        threat_types = data.get("threat_types", [])
                        message = data.get("message", "")

                        threat_type_list.extend(threat_types)

                        results.append({
                            "URL": url,
                            "Safe": "Safe" if is_safe else "Unsafe",
                            "Threat Types": ", ".join(threat_types) if threat_types else "None",
                            "Message": message
                        })
                except Exception as e:
                    results.append({
                        "URL": url,
                        "Safe": "Error",
                        "Threat Types": str(e),
                        "Message": "",
                    })

                progress_bar.progress(i / len(urls))

        progress_bar.empty()

        # Show results in a table with colored Safe status
        df_results = pd.DataFrame(results)
        st.subheader("🔎 Scan Results")
        st.dataframe(df_results.style.applymap(
            lambda x: 'background-color: #d4edda; color: #155724;' if x == "Safe" else
                      ('background-color: #f8d7da; color: #721c24;' if x == "Unsafe" else ''),
            subset=["Safe"]
        ), height=300)

        # Threat types distribution chart
        if threat_type_list:
            st.subheader("📊 Threat Types Distribution")
            threat_counts = pd.Series(threat_type_list).value_counts()
            fig = px.bar(
                threat_counts,
                x=threat_counts.index,
                y=threat_counts.values,
                labels={'x': 'Threat Type', 'y': 'Count'},
                title='Threat Types Distribution',
                color=threat_counts.index,
                color_discrete_sequence=px.colors.qualitative.Bold
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threats detected across scanned URLs.")

        # Summary counts
        safe_count = sum(1 for r in results if r["Safe"] == "Safe")
        unsafe_count = sum(1 for r in results if r["Safe"] == "Unsafe")
        error_count = sum(1 for r in results if r["Safe"] == "Error")

        st.success(f"✅ {safe_count} safe, ⚠️ {unsafe_count} unsafe, ❌ {error_count} errors.")
