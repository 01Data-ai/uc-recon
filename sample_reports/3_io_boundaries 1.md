# IO Boundaries — Attack Surface, Integration Seams & Vulnerability Points
**Target:** `/root/streamlit-agent-main/streamlit_agent`
**Analysis Date:** February 22, 2026
**Analyst:** UC Recon — Deep Forensics Mode
**Classification: FLAGSHIP REPORT**

---

## 1. Complete Attack Surface Map

```
EXTERNAL WORLD
     │
     ▼
┌─────────────────────────────────────────────────────────────────┐
│  BROWSER (HTTP/WebSocket to Streamlit server)                   │
│                                                                 │
│  INPUT VECTORS:                                                 │
│  ① st.chat_input()     → user prompts (all 9 modules)          │
│  ② st.text_input()     → API keys, DB URIs (all modules)       │
│  ③ st.file_uploader()  → uploaded files (chat_pandas, chat_doc)│
│  ④ st.selectbox()      → session key selection (mrkl_demo)     │
│  ⑤ st.form submit      → form text input (mrkl_demo)           │
│  ⑥ st.sidebar.*        → configuration inputs (all modules)    │
└────────────────────────┬────────────────────────────────────────┘
                         │
     ┌───────────────────┼───────────────────┐
     ▼                   ▼                   ▼
┌──────────┐       ┌──────────┐       ┌──────────────┐
│ OpenAI   │       │ LangSmith│       │ LangChain    │
│ API      │       │ Tracing  │       │ Hub          │
│ (HTTPS)  │       │ (HTTPS)  │       │ (HTTPS)      │
└──────────┘       └──────────┘       └──────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────┐
│  LOCAL RESOURCES                                                │
│  • Chinook.db (SQLite, read-only for local mode)               │
│  • User-supplied DB URI (SQLAlchemy — arbitrary RDBMS)         │
│  • Uploaded PDF files → tempfile.TemporaryDirectory            │
│  • Uploaded CSV/Excel files → pandas.read_csv/read_excel       │
│  • runs/*.pickle (local filesystem read)                       │
└─────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────┐
│  EXTERNAL WEB (via DuckDuckGo search tools)                    │
│  • minimal_agent.py → load_tools(["ddg-search"])               │
│  • search_and_chat.py → DuckDuckGoSearchRun                    │
│  • mrkl_demo.py → DuckDuckGoSearchAPIWrapper                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Input Boundary Details

### ① User Chat Prompts
All 9 modules accept user-controlled text via `st.chat_input()` or `st.text_input()`.

| Module | Variable | Destination | Risk |
|---|---|---|---|
| `basic_memory.py:55` | `prompt` (st.chat_input) | `chain_with_history.invoke({"question": prompt})` → OpenAI | Prompt injection |
| `basic_streaming.py:25` | `prompt` (st.chat_input) | `llm.invoke(st.session_state.messages)` → OpenAI | Prompt injection |
| `chat_pandas_df.py:63` | `prompt` (st.chat_input) | `pandas_df_agent.run(st.session_state.messages)` → **PythonAstREPLTool → exec()** | 🔴 RCE |
| `chat_with_documents.py:103` | `user_query` (st.chat_input) | `qa_chain.run(user_query)` → OpenAI + vector retrieval | Prompt injection |
| `chat_with_sql_db.py:71` | `user_query` (st.chat_input) | `agent.run(user_query)` → SQL agent → database | Prompt injection + SQL injection |
| `minimal_agent.py:12` | `prompt` (st.chat_input) | `agent.run(prompt)` → DuckDuckGo + OpenAI | Prompt injection, SSRF via search |
| `mrkl_demo.py:79` | `user_input` (st.text_input/selectbox) | `mrkl.invoke({"input": user_input})` → multi-tool agent | Prompt injection |
| `search_and_chat.py:39` | `prompt` (st.chat_input) | `executor.invoke(prompt, cfg)` → DuckDuckGo + OpenAI | Prompt injection, SSRF |
| `simple_feedback.py:50` | `input` (st.chat_input) | `llm_chain.invoke(input, cfg)` → OpenAI | Prompt injection |

### ② API Key Inputs
All modules accept OpenAI API keys via sidebar `st.text_input(type="password")`. These are:
- Stored unencrypted in `st.session_state`
- Sent to OpenAI HTTPS endpoint
- **Never validated format before use**

`simple_feedback.py` also accepts a LangChain API key (line 18-19) for LangSmith.

### ③ File Upload Boundary

**`chat_pandas_df.py` — lines 27-34:**
```python
@st.cache_data(ttl="2h")
def load_data(uploaded_file):
    try:
        ext = os.path.splitext(uploaded_file.name)[1][1:].lower()
    except:
        ext = uploaded_file.split(".")[-1]
    if ext in file_formats:
        return file_formats[ext](uploaded_file)
```
- `uploaded_file.name` is user-controlled; extension parsed from it
- Passed directly to `pd.read_csv`, `pd.read_excel` — no sanitization
- Bare `except:` swallows all exceptions silently

**`chat_with_documents.py` — lines 23-29:**
```python
temp_dir = tempfile.TemporaryDirectory()
for file in uploaded_files:
    temp_filepath = os.path.join(temp_dir.name, file.name)
    with open(temp_filepath, "wb") as f:
        f.write(file.getvalue())
    loader = PyPDFLoader(temp_filepath)
```
- `file.name` is user-controlled and joined to a temp path without sanitization
- If `file.name` contains `../` sequences, potential path traversal (OS-dependent mitigation by `tempfile`)
- File content written to disk then loaded by `PyPDFLoader`

### ④ Database URI Input

**`chat_with_sql_db.py` — lines 25-29:**
```python
db_uri = st.sidebar.text_input(
    label="Database URI", placeholder="mysql://user:pass@hostname:port/db"
)
```
**`chat_with_sql_db.py` — line 55:**
```python
return SQLDatabase.from_uri(database_uri=db_uri)
```
- User supplies an **arbitrary connection string** passed directly to SQLAlchemy
- Enables connection to: remote MySQL, PostgreSQL, arbitrary SQLite files, MSSQL, etc.
- No URI schema whitelist, no hostname restriction → **SSRF / unintended database access**

### ⑤ Pickle File Deserialization

**`callbacks/capturing_callback_handler.py` — lines 42-47:**
```python
def load_records_from_file(path: str) -> list[CallbackRecord]:
    with open(path, "rb") as file:
        records = pickle.load(file)
```
**`mrkl_demo.py` — lines 104-108:**
```python
session_path = Path(__file__).parent / "runs" / session_name
print(f"Playing saved session: {session_path}")
answer = playback_callbacks([st_callback], str(session_path), max_pause_time=2)
```
- `session_name` is looked up from `SAVED_SESSIONS` dict keyed on user input `user_input`
- If `user_input` matches a key, the corresponding pickle filename is loaded
- **The pickle files ship with the repo** — if tampered (supply chain), arbitrary Python executes on `pickle.load()`
- The path itself is fixed (`__file__.parent / "runs" / session_name`) so there is no direct path injection, but the deserialization boundary is dangerous

---

## 3. Outbound Integration Seams

| Endpoint | Module | Protocol | Data Sent | Risk |
|---|---|---|---|---|
| `api.openai.com` | ALL (via OpenAI SDK) | HTTPS | Full prompt + message history + user data | Data leakage, key theft |
| `api.smith.langchain.com` | `simple_feedback.py:29` | HTTPS | Full LLM traces, user messages, responses | Data leakage, tracing |
| `api.hub.langchain.com` | `mrkl_demo.py:71` via `hub.pull()` | HTTPS | Prompt template name | Supply-chain: prompt injection from hub |
| `duckduckgo.com` (via DDG API) | `minimal_agent.py`, `search_and_chat.py`, `mrkl_demo.py` | HTTPS | LLM-generated search queries | SSRF, data leakage |
| User-supplied RDBMS | `chat_with_sql_db.py:55` | User-defined | SQL queries from LLM agent | SSRF, data exfiltration |

---

## 4. Data Flow Through the System

### Flow A: Chat Pandas DF (Highest Risk)
```
User types prompt
  → st.chat_input()  [chat_pandas_df.py:63]
  → pandas_df_agent.run(messages)  [line 74]
  → LangChain PythonAstREPLTool
  → exec() on LLM-generated Python code
  → Arbitrary Python execution in server process
  → Response written to st.session_state + displayed
```

### Flow B: SQL Chat (High Risk)
```
User selects "Connect to your SQL database"
  → Enters arbitrary db_uri  [chat_with_sql_db.py:27]
  → configure_db(db_uri)  [line 48]
  → SQLDatabase.from_uri(database_uri=db_uri)  [line 55]
  → SQLAlchemy connects to remote host
  → User types question → agent.run(user_query)  [line 73]
  → SQL agent generates and executes SQL against connected DB
  → Results sent to OpenAI, response displayed
```

### Flow C: Document Chat (Medium Risk)
```
User uploads PDF(s)
  → file.name appended to temp dir path  [chat_with_documents.py:24]
  → File written to temp_filepath  [line 26]
  → PyPDFLoader reads file
  → Text chunked → embedded (HuggingFace model)
  → Stored in DocArrayInMemorySearch (in-process)
  → User query → ConversationalRetrievalChain
  → Relevant chunks + user question → OpenAI → response
```

### Flow D: MRKL Demo Pickle Replay (High Risk)
```
User selects pre-canned question matching SAVED_SESSIONS key
  → session_name = SAVED_SESSIONS[user_input]
  → session_path = .../runs/{session_name}
  → pickle.load(open(session_path, "rb"))  [capturing_callback_handler.py:44]
  → CallbackRecords deserialized
  → Playback dispatched to StreamlitCallbackHandler
```

---

## 5. Vulnerability Point Summary

| ID | Location | Type | Severity |
|---|---|---|---|
| VUL-01 | `chat_pandas_df.py:74` | Arbitrary Code Execution via PythonAstREPLTool | 🔴 CRITICAL |
| VUL-02 | `chat_with_sql_db.py:55` | SSRF / Unvalidated DB URI → SQLAlchemy | 🔴 HIGH |
| VUL-03 | `callbacks/capturing_callback_handler.py:44` | Unsafe Pickle Deserialization | 🔴 HIGH |
| VUL-04 | `chat_with_documents.py:24` | Path Traversal in uploaded filename | 🟠 HIGH |
| VUL-05 | `minimal_agent.py:6` | Missing API key guard — LLM runs with `OPENAI_API_KEY` env var silently | 🟠 HIGH |
| VUL-06 | `mrkl_demo.py:46` | Fallback `openai_api_key = "not_supplied"` — misleading, may still attempt calls | 🟡 MEDIUM |
| VUL-07 | `chat_with_sql_db.py:25-29` | No DB URI validation / whitelist | 🟡 MEDIUM |
| VUL-08 | `mrkl_demo.py:71` | `hub.pull()` fetches from internet at runtime | 🟡 MEDIUM |
| VUL-09 | ALL modules | No authentication / access control | 🟠 HIGH |
| VUL-10 | `simple_feedback.py:29` | User data sent to LangSmith without explicit user consent notice | 🟡 MEDIUM |
| VUL-11 | `chat_pandas_df.py:29` | Bare `except:` silently swallows errors in file loading | 🟡 LOW |
| VUL-12 | `basic_streaming.py:17` | API key accepted without `st.secrets` fallback — always exposed in sidebar | 🟡 LOW |
