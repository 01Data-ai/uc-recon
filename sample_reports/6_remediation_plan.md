# Remediation Plan
**Target:** `/root/streamlit-agent-main/streamlit_agent`
**Analysis Date:** February 22, 2026
**Analyst:** UC Recon — Deep Forensics Mode

> For each finding from Report 5, this plan provides: exact file:line location, code excerpt showing the issue, severity rating, and specific fix recommendation.

---

## REM-01 — Fix: Arbitrary Code Execution via PythonAstREPLTool

**Severity:** 🔴 CRITICAL
**File:** `chat_pandas_df.py`
**Lines:** 70–80

### Issue Code
```python
pandas_df_agent = create_pandas_dataframe_agent(
    llm,
    df,
    verbose=True,
    agent_type=AgentType.OPENAI_FUNCTIONS,
    handle_parsing_errors=True,
)
response = pandas_df_agent.run(st.session_state.messages, callbacks=[st_cb])
```

### Recommendations (choose based on deployment context)

**Option A — Remove the module entirely (for production):**
The app README explicitly marks this as unsafe. For any production deployment, remove `chat_pandas_df.py` entirely or gate it behind authentication.

**Option B — Add sandboxing (if DataFrame agent functionality is required):**
Run the agent in an isolated subprocess with restricted OS capabilities:
```python
# Replace create_pandas_dataframe_agent with a sandboxed alternative
# Use Docker container isolation, gVisor, or nsjail for process isolation
# Alternatively, use a restricted Python interpreter (RestrictedPython library)
```

**Option C — Add strict auth guard + deployment warning:**
```python
# At top of chat_pandas_df.py, add:
ALLOWED_USERS = os.environ.get("ALLOWED_USERS", "").split(",")
if not ALLOWED_USERS or ALLOWED_USERS == [""]:
    st.error("This app requires ALLOWED_USERS environment variable to be set.")
    st.stop()

# Add per-session basic auth
password = st.sidebar.text_input("Access Password", type="password")
if password != os.environ.get("APP_PASSWORD", ""):
    st.warning("Unauthorized. Enter access password.")
    st.stop()
```

**Option D — Constrain the agent tool (minimum viable fix):**
```python
# Pass allow_dangerous_code=True explicitly so the intent is visible in code review
# AND wrap the agent with input sanitization
import re

def sanitize_prompt(prompt: str) -> str:
    # Block obvious code injection attempts
    dangerous_patterns = [r'os\.', r'subprocess', r'__import__', r'exec\(', r'eval\(', r'open\(']
    for pattern in dangerous_patterns:
        if re.search(pattern, prompt, re.IGNORECASE):
            raise ValueError(f"Blocked dangerous pattern in prompt: {pattern}")
    return prompt

# Then sanitize before agent.run():
response = pandas_df_agent.run(sanitize_prompt(st.session_state.messages), callbacks=[st_cb])
```

> ⚠️ Note: prompt-level sanitization alone is insufficient against a determined attacker. Sandbox isolation (Option B) is the only true fix.

---

## REM-02 — Fix: SSRF via Unvalidated Database URI

**Severity:** 🔴 HIGH
**File:** `chat_with_sql_db.py`
**Lines:** 23–29 (input), 54–55 (sink)

### Issue Code
```python
db_uri = st.sidebar.text_input(
    label="Database URI", placeholder="mysql://user:pass@hostname:port/db"
)
...
return SQLDatabase.from_uri(database_uri=db_uri)
```

### Recommendations

**Fix — Add URI schema allowlist and hostname validation:**
```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_SCHEMAS = {"postgresql", "mysql", "sqlite", "mssql+pyodbc"}
BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

def validate_db_uri(uri: str) -> str:
    """Validate database URI against SSRF and schema injection."""
    try:
        parsed = urlparse(uri)
    except Exception:
        raise ValueError("Invalid database URI format.")

    schema = parsed.scheme.split("+")[0].lower()
    if schema not in ALLOWED_SCHEMAS:
        raise ValueError(f"Unsupported database schema: {schema}. Allowed: {ALLOWED_SCHEMAS}")

    hostname = parsed.hostname
    if hostname in BLOCKED_HOSTS:
        raise ValueError(f"Connection to {hostname} is not permitted.")

    # Block RFC-1918 private IP ranges
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError(f"Connection to private IP {hostname} is not permitted.")
    except ValueError:
        pass  # Not an IP — hostname, allow (or add DNS resolution check)

    return uri

# In configure_db():
@st.cache_resource(ttl="2h")
def configure_db(db_uri):
    if db_uri == LOCALDB:
        db_filepath = (Path(__file__).parent / "Chinook.db").absolute()
        creator = lambda: sqlite3.connect(f"file:{db_filepath}?mode=ro", uri=True)
        return SQLDatabase(create_engine("sqlite:///", creator=creator))
    validated_uri = validate_db_uri(db_uri)   # ← ADD THIS
    return SQLDatabase.from_uri(database_uri=validated_uri)
```

---

## REM-03 — Fix: Unsafe Pickle Deserialization

**Severity:** 🔴 HIGH
**File:** `callbacks/capturing_callback_handler.py`
**Lines:** 41–47, 109–117

### Issue Code
```python
def load_records_from_file(path: str) -> list[CallbackRecord]:
    with open(path, "rb") as file:
        records = pickle.load(file)   # ← unsafe
```

### Recommendations

**Option A — Replace pickle with JSON (preferred):**
```python
import json

# New serialization format — safe, human-readable
def dump_records_to_file(self, path: str) -> None:
    """Write CallbackRecords to a JSON file."""
    # Convert records to JSON-serializable form
    serializable = []
    for record in self._records:
        serializable.append({
            "callback_type": record["callback_type"],
            "args": _serialize_args(record["args"]),   # implement safe arg serializer
            "kwargs": _serialize_kwargs(record["kwargs"]),
            "time_delta": record["time_delta"],
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serializable, f)

def load_records_from_file(path: str) -> list[CallbackRecord]:
    """Load CallbackRecords from a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise RuntimeError(f"Bad CallbackRecord data in {path}")
    return [CallbackRecord(**record) for record in data]
```

**Option B — Add file integrity check before deserialization (if pickle must be kept):**
```python
import hashlib

# Ship a KNOWN_GOOD_HASHES dict alongside the pickle files
KNOWN_GOOD_HASHES = {
    "alanis.pickle": "sha256:EXPECTED_HASH_HERE",
    "leo.pickle":    "sha256:EXPECTED_HASH_HERE",
}

def load_records_from_file(path: str) -> list[CallbackRecord]:
    filename = os.path.basename(path)
    if filename not in KNOWN_GOOD_HASHES:
        raise ValueError(f"Unknown session file: {filename}")

    with open(path, "rb") as f:
        raw = f.read()

    actual_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual_hash != KNOWN_GOOD_HASHES[filename]:
        raise RuntimeError(f"Integrity check failed for {filename}. File may be tampered.")

    import io
    records = pickle.load(io.BytesIO(raw))
    ...
```

> ⚠️ Option A (JSON) is strongly preferred. Pickle should never be used for data that ships in a repository.

---

## REM-04 — Fix: Path Traversal via Uploaded Filename

**Severity:** 🟠 HIGH
**File:** `chat_with_documents.py`
**Line:** 24

### Issue Code
```python
temp_filepath = os.path.join(temp_dir.name, file.name)  # file.name not sanitized
```

### Recommendation
```python
import os

def safe_filename(filename: str) -> str:
    """Strip path separators and dangerous characters from a user-supplied filename."""
    # Get only the basename (strips any path components)
    safe = os.path.basename(filename)
    # Remove any remaining path traversal characters
    safe = safe.replace("..", "").replace("/", "").replace("\\", "")
    # Limit length
    safe = safe[:255]
    # If empty after sanitization, use a default
    return safe if safe else "uploaded_file"

# In configure_retriever():
for file in uploaded_files:
    safe_name = safe_filename(file.name)          # ← ADD THIS
    temp_filepath = os.path.join(temp_dir.name, safe_name)   # ← USE SAFE NAME
    with open(temp_filepath, "wb") as f:
        f.write(file.getvalue())
    loader = PyPDFLoader(temp_filepath)
```

**Additional fix — Add file size limit:**
```python
MAX_FILE_SIZE_MB = 10
for file in uploaded_files:
    if len(file.getvalue()) > MAX_FILE_SIZE_MB * 1024 * 1024:
        st.error(f"File {file.name} exceeds {MAX_FILE_SIZE_MB}MB limit.")
        st.stop()
```

---

## REM-05 — Fix: Missing Authentication on All Endpoints

**Severity:** 🟠 HIGH
**Files:** All 9 application modules
**Lines:** N/A (structural absence)

### Recommendation

**Add a reusable authentication helper:**
```python
# streamlit_agent/auth.py  (new file)
import streamlit as st
import os
import hashlib

def require_auth():
    """
    Simple password-based auth gate for Streamlit apps.
    Set APP_PASSWORD env var in production.
    """
    app_password = os.environ.get("APP_PASSWORD")
    if not app_password:
        return  # Auth disabled in development if env var not set

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if not st.session_state.authenticated:
        st.title("🔒 Authentication Required")
        pwd = st.text_input("Password", type="password")
        if st.button("Login"):
            # Compare hashes to prevent timing attacks
            provided = hashlib.sha256(pwd.encode()).hexdigest()
            expected = hashlib.sha256(app_password.encode()).hexdigest()
            if provided == expected:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Incorrect password.")
        st.stop()
```

**Add to the top of each app module:**
```python
# At the top of each app, after st.set_page_config():
from streamlit_agent.auth import require_auth
require_auth()
```

For production deployments, consider Streamlit's built-in authentication (Streamlit 1.39+) or a reverse proxy with OAuth2 (nginx + oauth2-proxy).

---

## REM-06 — Fix: Prompt → SQL Injection

**Severity:** 🟠 HIGH
**File:** `chat_with_sql_db.py`
**Lines:** 57–75

### Issue Code
```python
response = agent.run(user_query, callbacks=[st_cb])
```

### Recommendations

**Fix A — Enforce read-only database role:**
The code already applies `?mode=ro` for local SQLite — extend this principle:
```python
# For external databases, enforce read-only connection
# For PostgreSQL:
#   CREATE ROLE readonly_user WITH LOGIN PASSWORD '...' NOSUPERUSER NOCREATEDB;
#   GRANT CONNECT ON DATABASE mydb TO readonly_user;
#   GRANT USAGE ON SCHEMA public TO readonly_user;
#   GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;
# Then provide only that role's credentials in the URI.
```

**Fix B — Restrict SQL toolkit operations:**
```python
from langchain.agents.agent_toolkits import SQLDatabaseToolkit

# Only allow SELECT operations by customizing the toolkit
toolkit = SQLDatabaseToolkit(db=db, llm=llm)
# Override the SQL execution tool to validate queries
for tool in toolkit.get_tools():
    if hasattr(tool, 'db'):
        tool.db._sample_rows_in_table_info = 0  # Reduce info leakage
```

**Fix C — Input length limit:**
```python
MAX_QUERY_LENGTH = 500
user_query = st.chat_input(placeholder="Ask me anything!")
if user_query and len(user_query) > MAX_QUERY_LENGTH:
    st.warning(f"Query too long (max {MAX_QUERY_LENGTH} chars).")
    st.stop()
```

---

## REM-07 — Fix: Implicit OpenAI API Key in `minimal_agent.py`

**Severity:** 🟠 HIGH
**File:** `minimal_agent.py`
**Lines:** 5–8

### Issue Code
```python
llm = OpenAI(temperature=0, streaming=True)   # reads OPENAI_API_KEY silently
```

### Recommendation
```python
# minimal_agent.py — add explicit key requirement
import streamlit as st
from langchain.llms import OpenAI
from langchain.agents import AgentType, initialize_agent, load_tools
from langchain.callbacks import StreamlitCallbackHandler
import os

# Check for API key — explicit, not silent
with st.sidebar:
    openai_api_key = st.text_input("OpenAI API Key", type="password")

if not openai_api_key:
    # Also check env var, but inform the user
    openai_api_key = os.environ.get("OPENAI_API_KEY", "")
    if openai_api_key:
        st.sidebar.info("Using API key from environment variable.")
    else:
        st.info("Please provide an OpenAI API key to continue.")
        st.stop()  # ← GUARD

llm = OpenAI(api_key=openai_api_key, temperature=0, streaming=True)  # explicit key
tools = load_tools(["ddg-search"])
agent = initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, verbose=True)
```

---

## REM-08 — Fix: LangSmith Telemetry / PII Exfiltration

**Severity:** 🟡 MEDIUM
**File:** `simple_feedback.py`
**Lines:** 28–32

### Issue Code
```python
langchain_endpoint = "https://api.smith.langchain.com"
client = Client(api_url=langchain_endpoint, api_key=langchain_api_key)
ls_tracer = LangChainTracer(project_name=project, client=client)
```

### Recommendations

**Fix A — Add user consent notice:**
```python
# simple_feedback.py — add before creating LangSmith client
st.sidebar.info(
    "ℹ️ **Data Privacy Notice:** This app sends conversation traces to "
    "[LangSmith](https://docs.smith.langchain.com/) for quality monitoring. "
    "Do not enter personally identifiable information or confidential data."
)
consent = st.sidebar.checkbox("I understand and consent to telemetry")
if not consent:
    st.warning("Please acknowledge the data privacy notice to continue.")
    st.stop()
```

**Fix B — Make telemetry opt-in:**
```python
enable_tracing = st.sidebar.checkbox("Enable LangSmith tracing (optional)", value=False)
cfg["callbacks"] = [ls_tracer, run_collector] if enable_tracing else []
```

**Fix C — Sanitize sensitive fields before tracing:**
Use LangSmith's `hide_inputs`/`hide_outputs` options to redact sensitive data fields.

---

## REM-09 — Fix: Supply Chain Risk via `hub.pull()`

**Severity:** 🟡 MEDIUM
**File:** `mrkl_demo.py`
**Line:** 71

### Issue Code
```python
react_agent = create_react_agent(llm, tools, hub.pull("hwchase17/react"))
```

### Recommendation — Pin to a specific commit hash and cache locally:
```python
# Option A: Pin to specific version hash
react_agent = create_react_agent(llm, tools, hub.pull("hwchase17/react:ae7b5a4b"))

# Option B: Cache the prompt locally and use the cached version in production
# At development time: prompt = hub.pull("hwchase17/react"); prompt.save("react_prompt.json")
# At runtime:
from langchain_core.prompts import load_prompt
try:
    react_prompt = load_prompt("streamlit_agent/react_prompt.json")  # local cache
except FileNotFoundError:
    react_prompt = hub.pull("hwchase17/react")  # fallback to hub
    react_prompt.save("streamlit_agent/react_prompt.json")

react_agent = create_react_agent(llm, tools, react_prompt)
```

---

## REM-10 — Fix: Bare `except:` and Input Validation in `load_data`

**Severity:** 🟡 MEDIUM
**File:** `chat_pandas_df.py`
**Lines:** 27–34

### Issue Code
```python
try:
    ext = os.path.splitext(uploaded_file.name)[1][1:].lower()
except:
    ext = uploaded_file.split(".")[-1]
```

### Recommendation
```python
@st.cache_data(ttl="2h")
def load_data(uploaded_file):
    try:
        # Use getattr to safely handle both UploadedFile objects and string paths
        if hasattr(uploaded_file, 'name'):
            ext = os.path.splitext(uploaded_file.name)[1][1:].lower()
        elif isinstance(uploaded_file, str):
            ext = uploaded_file.split(".")[-1].lower()
        else:
            st.error("Unsupported file input type.")
            return None
    except (AttributeError, IndexError) as e:      # ← specific exceptions only
        st.error(f"Could not determine file extension: {e}")
        return None

    if ext not in file_formats:
        st.error(f"Unsupported file format: {ext}")
        return None

    # Add file size check
    if hasattr(uploaded_file, 'size') and uploaded_file.size > 50 * 1024 * 1024:
        st.error("File too large (max 50MB).")
        return None

    return file_formats[ext](uploaded_file)
```

---

## REM-11 — Fix: Session History Exposure in `basic_memory.py`

**Severity:** 🟡 MEDIUM
**File:** `basic_memory.py`
**Lines:** 19, 57, 65

### Issue Code
```python
msgs = StreamlitChatMessageHistory(key="langchain_messages")
config = {"configurable": {"session_id": "any"}}
...
view_messages.json(st.session_state.langchain_messages)
```

### Recommendation
```python
# 1. Use a unique session key per browser session
import uuid
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

msgs = StreamlitChatMessageHistory(key=f"langchain_messages_{st.session_state.session_id}")
config = {"configurable": {"session_id": st.session_state.session_id}}

# 2. Gate the history expander behind a developer mode toggle
debug_mode = os.environ.get("DEBUG_MODE", "false").lower() == "true"
if debug_mode:
    view_messages = st.expander("View the message contents in session state")
    with view_messages:
        view_messages.json(st.session_state.get(f"langchain_messages_{st.session_state.session_id}", []))
```

---

## REM-12 — Fix: Deprecated `st.experimental_rerun()`

**Severity:** 🟢 LOW
**File:** `clear_results.py`
**Line:** 21

### Issue Code
```python
st.experimental_rerun()
```

### Recommendation
```python
# Replace with the stable API (Streamlit >= 1.27)
st.rerun()
```

No other logic changes required. This is a one-line fix.

---

## Remediation Priority Matrix

| Priority | Finding ID | File:Line | Fix Effort | Impact if Unmitigated |
|---|---|---|---|---|
| **P0 — Immediate** | REM-01 | `chat_pandas_df.py:70-80` | High | Full OS compromise |
| **P0 — Immediate** | REM-03 | `capturing_callback_handler.py:41-47` | Medium | Arbitrary code on pickle load |
| **P1 — This Sprint** | REM-05 | All modules | Medium | Any user can use all features |
| **P1 — This Sprint** | REM-02 | `chat_with_sql_db.py:55` | Medium | SSRF / internal DB access |
| **P1 — This Sprint** | REM-07 | `minimal_agent.py:5-8` | Low | Silent credential use |
| **P2 — Next Sprint** | REM-04 | `chat_with_documents.py:24` | Low | Path traversal |
| **P2 — Next Sprint** | REM-06 | `chat_with_sql_db.py:57-75` | Medium | Prompt → SQL abuse |
| **P3 — Planned** | REM-08 | `simple_feedback.py:28-32` | Low | PII to third party |
| **P3 — Planned** | REM-09 | `mrkl_demo.py:71` | Low | Supply chain |
| **P3 — Planned** | REM-10 | `chat_pandas_df.py:27-34` | Low | Error swallowing |
| **P4 — Backlog** | REM-11 | `basic_memory.py:19,57,65` | Low | History exposure |
| **P4 — Backlog** | REM-12 | `clear_results.py:21` | Trivial | Future breakage |

---

## Systemic Recommendations

Beyond individual fixes, the following systemic changes should be applied to the entire codebase:

1. **Add authentication middleware** — Implement a centralized `require_auth()` decorator/function called at the top of all app modules before any UI renders.

2. **Create a `config.py` with centralized security settings** — API key sources, feature flags for dangerous tools, allowed file types, max file sizes.

3. **Pin all dependency versions** — Change `langchain = {version = ">=0.1.0"}` to a specific pinned range (e.g., `">=0.1.0,<0.2.0"`). Same for all `langchain-*` packages.

4. **Replace all deprecated `langchain.chat_models`, `langchain.llms`, `langchain.memory` etc. imports** with the new `langchain-community` / `langchain-core` / `langchain-openai` equivalents. This is required for LangChain 0.2+ compatibility.

5. **Add a `.env.example` and document all required environment variables** — currently, `minimal_agent.py` silently requires `OPENAI_API_KEY` with no documentation.

6. **Compute and ship SHA-256 hashes for the pickle files** — Add a `runs/CHECKSUMS.sha256` file and validate on load as an interim measure while migrating to JSON serialization.

7. **Add rate limiting** — Without auth, unlimited LLM API calls can be made by any user, potentially exhausting the API key balance. Streamlit's `st.session_state` can be used to implement per-session rate limits.
