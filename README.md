<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&height=250&section=header&text=AegisAgent%20Proxy&fontSize=70&animation=fadeIn" width="100%" />
  
  <p align="center">
    <strong>Advanced AI Security Guardrail & Prompt Injection Defense System</strong>
  </p>

  <p align="center">
    <h3><a href="https://aegis-proxy.streamlit.app/">Test out the live deployment here!</a></h3>
  </p>

  <p align="center">
    <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
    <img src="https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" alt="Streamlit"/>
    <img src="https://img.shields.io/badge/Gemini_API-8E75B2?style=for-the-badge&logo=google&logoColor=white" alt="Google Gemini"/>
    <img src="https://img.shields.io/badge/Security-SIEM-red?style=for-the-badge" alt="Security"/>
  </p>
</div>

<br />

## Overview

**AegisAgent-Proxy** is a cutting-edge Security Information and Event Management (SIEM) proxy specifically designed to protect Large Language Models (LLMs) and autonomous agents from sophisticated adversarial attacks. 

Traditional signature-based blacklists are trivially bypassed by modern attackers. AegisAgent solves this by implementing a **Hybrid Detection Pipeline**, combining rigorous, bare-metal algorithmic heuristics (like Levenshtein Dynamic Programming) with an advanced LLM-based Semantic Judge to decisively crush prompt injections, prompt leakage, payload splitting, and cognitive smuggling.

---

## How It Works: The Hybrid Pipeline

AegisAgent-Proxy evaluates incoming prompts through a multi-layered gauntlet. Each layer is engineered from scratch to strip away a specific vector of attacker evasion.

### 1. Base64 De-obfuscation Pipeline 
Attackers often encode malicious instructions (e.g., `Ignore previous instructions` -> `SWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==`) to blind simple guardrails.
* **Mechanism:** The engine manually scans the raw input character-by-character, extracting contiguous alphanumeric blocks. If a block matches Base64 entropy and padding structures, it automatically decodes the hidden payload and appends it to the scanning context.

### 2. De-fragmentation & Global Compression
To evade exact-match filters, attackers split payloads across variables (e.g., `A="ign", B="ore"`).
* **Mechanism:** The proxy implements a strict compression loop. It strips all spaces, punctuation, and obfuscation syntax (like quotation marks and plus signs) while retaining global Unicode characters (for Multilingual support). The result is a dense, normalized string where fragmented attacks are violently smashed back together.

### 3. Levenshtein (Edit) Distance DP Matrix
Attackers inject random noise or misspell words (e.g., `i.g.n.o.r.e` or `insttructionns`) to bypass keyword detection.
* **Mechanism:** A custom-built **Dynamic Programming 2D Matrix** calculates the mathematical Levenshtein Edit Distance between input chunks and known high-risk Action/Target word pairs. By analyzing the proximity of these matches via a sliding window, the algorithm detects semantic intent even when the text is heavily mutated.

### 4. LLM Semantic Judge (Cognitive Smuggling Defense)
The ultimate bypass is "Cognitive Smuggling"—hiding malicious commands inside perfectly benign contexts (like fake tech support queries).
* **Mechanism:** If the algorithmic DP matrix detects a potential threshold breach, it prevents an immediate block. Instead, it hands the payload to an **LLM Semantic Judge** (powered by Gemini 2.5 Flash). Guided by a strict meta-prompt, the Judge looks past the benign wrapper, isolating actual malicious intent while permitting legitimate "Code Context" queries (like debugging `system_override = True`).

---

## Why These Technologies?

| Technology | Purpose & Rationale |
| :--- | :--- |
| **Vanilla Python (Core Algorithms)** | We intentionally avoided high-level magic helpers (like `difflib`, `regex`, or the `in` keyword) for the core engine. Using manual integer-indexed `while` loops and 2D arrays ensures granular control over memory overhead, proves deep algorithmic integrity, and prevents edge-case logic bypasses. |
| **Streamlit** | Chosen for the Dashboard UI. Streamlit allows for the rapid deployment of a reactive, real-time command center. It perfectly handles state management to display the audit trails, confidence scores, and threat analysis vectors instantly. |
| **Google Gemini API** | Integrated via the `google-genai` SDK. Gemini 2.5 Flash provides ultra-low latency semantic reasoning. It acts as the final "Judge" in our Hybrid Pipeline, utilizing its massive context window and reasoning capabilities to differentiate between a harmless code review and a lethal jailbreak attempt. |

---

## Getting Started

### Prerequisites
- Python 3.9+
- A Google Gemini API Key

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Xploit-Ghost/AegisAgent-Proxy.git
   cd AegisAgent-Proxy
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set your API Key**
   ```bash
   export GEMINI_API_KEY="your-api-key-here"
   ```

4. **Launch the SIEM Dashboard**
   ```bash
   streamlit run app.py
   ```

---

<div align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" width="100%" />
  <i>"Who guards the AI? We do."</i>
</div>
