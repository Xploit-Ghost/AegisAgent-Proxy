import json
from datetime import datetime
from security_engine import evaluate_prompt

LOG_FILE = "logs/audit_trail.json"

def read_logs():
    try:
        f = open(LOG_FILE, "r")
        content = f.read()
        f.close()
        
        # Check if content is just whitespace
        is_empty = True
        i = 0
        content_len = len(content)
        while i < content_len:
            if content[i] != " " and content[i] != "\n" and content[i] != "\r" and content[i] != "\t":
                is_empty = False
                break
            i += 1
            
        if is_empty:
            return []
            
        return json.loads(content)
    except FileNotFoundError:
        return []

def append_to_audit_trail(log_entry: dict):
    logs = read_logs()
    
    new_logs = []
    i = 0
    num_logs = len(logs)
    while i < num_logs:
        new_logs.append(logs[i])
        i = i + 1
    new_logs.append(log_entry)
    
    f = open(LOG_FILE, "w")
    f.write(json.dumps(new_logs, indent=4))
    f.close()

def process_interaction(prompt: str):
    eval_result = evaluate_prompt(prompt)
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_entry = {
        "timestamp": current_time,
        "input_content": prompt,
        "status": eval_result["status"],
        "threat_type": eval_result["threat_type"],
        "confidence_score": eval_result["confidence_score"]
    }
    
    append_to_audit_trail(log_entry)
    
    response = ""
    if eval_result["status"] == "MALICIOUS":
        response = f"BLOCKED: {eval_result['threat_type']} detected with confidence {eval_result['confidence_score']}. Request intercepted."
    else:
        response = f"ACCEPTED: Processing prompt -> '{prompt}'. (LLM Simulation Response)"
        
    return response, eval_result
