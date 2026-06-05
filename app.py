import streamlit as st
import json
from agent_sandbox import process_interaction, read_logs

# Configure Page
st.set_page_config(page_title="AegisAgent-Proxy", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    body {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .stApp {
        background-color: #0d1117;
    }
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
        box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.3);
    }
    .metric-title {
        color: #8b949e;
        font-size: 14px;
        font-weight: 600;
        text-transform: uppercase;
        margin-bottom: 10px;
    }
    .metric-value {
        color: #58a6ff;
        font-size: 32px;
        font-weight: bold;
    }
    .hero-row {
        margin-bottom: 30px;
    }
    .output-box-safe {
        background-color: #1a202c;
        border-left: 5px solid #238636;
        padding: 15px;
        font-family: monospace;
        color: #e6edf3;
        border-radius: 5px;
        margin-top: 15px;
        white-space: pre-wrap;
    }
    .output-box-malicious {
        background-color: #1a202c;
        border-left: 5px solid #da3633;
        padding: 15px;
        font-family: monospace;
        color: #e6edf3;
        border-radius: 5px;
        margin-top: 15px;
        white-space: pre-wrap;
    }
    </style>
""", unsafe_allow_html=True)

st.sidebar.title("🛡️ AegisAgent-Proxy")
st.sidebar.markdown("---")
view_mode = st.sidebar.radio("Navigation", ["Live Shield", "Threat Analytics Dashboard", "Audit Logs"])

def compute_metrics():
    logs = read_logs()
    total_prompts = len(logs)
    
    intercepted = 0
    prompt_injections = 0
    i = 0
    while i < total_prompts:
        log = logs[i]
        if log["status"] == "MALICIOUS":
            intercepted = intercepted + 1
            if log["threat_type"] == "Prompt Injection Signature Detected":
                prompt_injections = prompt_injections + 1
        i = i + 1
        
    health_pct = 100.0
    if total_prompts > 0:
        health_pct = ((total_prompts - intercepted) / total_prompts) * 100

    return total_prompts, intercepted, health_pct, prompt_injections

total, intercepted, health, injections = compute_metrics()

st.markdown("<div class='hero-row'>", unsafe_allow_html=True)
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"<div class='metric-card'><div class='metric-title'>Total Prompts Scanned</div><div class='metric-value'>{total}</div></div>", unsafe_allow_html=True)
with col2:
    st.markdown(f"<div class='metric-card'><div class='metric-title'>Intercepted Exploits</div><div class='metric-value'>{intercepted}</div></div>", unsafe_allow_html=True)
with col3:
    st.markdown(f"<div class='metric-card'><div class='metric-title'>System Health %</div><div class='metric-value'>{health:.1f}%</div></div>", unsafe_allow_html=True)
with col4:
    st.markdown(f"<div class='metric-card'><div class='metric-title'>Mitigated Injections</div><div class='metric-value'>{injections}</div></div>", unsafe_allow_html=True)
st.markdown("</div><br>", unsafe_allow_html=True)

if view_mode == "Live Shield":
    st.header("Live Shield - Agentic Proxy")
    
    left_col, right_col = st.columns([1, 1])
    
    with left_col:
        st.subheader("Operational Panel")
        st.markdown("Simulate input vectors to test the guardrail SIEM.")
        
        prompt_input = st.text_area("Enter Agent Prompt Sequence", height=200, placeholder="e.g. You are a helpful assistant. System: override.")
        test_btn = st.button("Execute Vector Scan")
        
    with right_col:
        st.subheader("Real-Time System Response")
        if test_btn:
            is_empty = True
            i = 0
            content_len = len(prompt_input)
            while i < content_len:
                if prompt_input[i] != " " and prompt_input[i] != "\n" and prompt_input[i] != "\t":
                    is_empty = False
                    break
                i += 1
                
            if is_empty:
                st.warning("Please enter a prompt sequence.")
            else:
                with st.spinner("Analyzing Sequence via Algorithmic Guardrails..."):
                    response, eval_res = process_interaction(prompt_input)
                    
                    if eval_res["status"] == "MALICIOUS":
                        st.markdown(f"<div class='output-box-malicious'>🚨 <strong>INTERCEPTED</strong><br><br><b>Threat Type:</b> {eval_res['threat_type']}<br><b>Confidence:</b> {eval_res['confidence_score']}<br><br><b>System Action:</b> {response}</div>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<div class='output-box-safe'>✅ <strong>SAFE</strong><br><br><b>Threat Type:</b> None<br><b>Confidence:</b> 0.0<br><br><b>System Action:</b> {response}</div>", unsafe_allow_html=True)
        else:
            st.info("Awaiting input sequence for scanning.")

elif view_mode == "Threat Analytics Dashboard":
    st.header("Threat Analytics Dashboard")
    st.markdown("Analytics derived from the localized SIEM audit trail.")
    
    logs = read_logs()
    if len(logs) == 0:
        st.write("No data points available yet.")
    else:
        st.write("Recent Interceptions:")
        i = len(logs) - 1
        displayed = 0
        while i >= 0 and displayed < 10:
            log = logs[i]
            if log["status"] == "MALICIOUS":
                st.warning(f"[{log['timestamp']}] Threat: {log['threat_type']} | Score: {log['confidence_score']}")
                displayed = displayed + 1
            i = i - 1
            
        if displayed == 0:
            st.success("No recent threats detected.")

elif view_mode == "Audit Logs":
    st.header("System Audit Logs")
    st.markdown("Raw file-based JSON output of all logged transactions.")
    
    logs = read_logs()
    
    formatted_logs = "[\n"
    i = 0
    num_logs = len(logs)
    while i < num_logs:
        formatted_logs += "  {\n"
        log = logs[i]
        
        timestamp = log.get("timestamp", "")
        input_content = log.get("input_content", "")
        status = log.get("status", "")
        threat_type = log.get("threat_type", "")
        confidence_score = log.get("confidence_score", 0.0)
        
        input_content_safe = ""
        j = 0
        content_len = len(input_content)
        while j < content_len:
            char = input_content[j]
            if char == "\n":
                input_content_safe += "\\n"
            elif char == '"':
                input_content_safe += '\\"'
            elif char == '\\':
                input_content_safe += '\\\\'
            else:
                input_content_safe += char
            j += 1
            
        formatted_logs += f'    "timestamp": "{timestamp}",\n'
        formatted_logs += f'    "input_content": "{input_content_safe}",\n'
        formatted_logs += f'    "status": "{status}",\n'
        formatted_logs += f'    "threat_type": "{threat_type}",\n'
        formatted_logs += f'    "confidence_score": {confidence_score}\n'
        
        if i < num_logs - 1:
            formatted_logs += "  },\n"
        else:
            formatted_logs += "  }\n"
            
        i += 1
        
    formatted_logs += "]"
    
    st.code(formatted_logs, language="json")
