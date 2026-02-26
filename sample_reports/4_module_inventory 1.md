# Module Inventory — Complete List + TOP 20 Risk Modules
**Target:** `/root/streamlit-agent-main/streamlit_agent`
**Analysis Date:** February 22, 2026
**Analyst:** UC Recon — Deep Forensics Mode

---

## 1. Complete Module Inventory

| # | Module Path | Size (bytes) | Type | Risk Rank |
|---|---|---|---|---|
| 1 | `streamlit_agent/chat_pandas_df.py` | 2,745 | Streamlit App | 🔴 #1 |
| 2 | `streamlit_agent/chat_with_sql_db.py` | 3,068 | Streamlit App | 🔴 #2 |
| 3 | `streamlit_agent/callbacks/capturing_callback_handler.py` | 6,663 | Utility / Library | 🔴 #3 |
| 4 | `streamlit_agent/mrkl_demo.py` | 4,196 | Streamlit App | 🟠 #4 |
| 5 | `streamlit_agent/chat_with_documents.py` | 4,480 | Streamlit App | 🟠 #5 |
| 6 | `streamlit_agent/minimal_agent.py` | 629 | Streamlit App | 🟠 #6 |
| 7 | `streamlit_agent/simple_feedback.py` | 3,156 | Streamlit App | 🟡 #7 |
| 8 | `streamlit_agent/search_and_chat.py` | 2,525 | Streamlit App | 🟡 #8 |
| 9 | `streamlit_agent/basic_memory.py` | 2,703 | Streamlit App | 🟡 #9 |
| 10 | `streamlit_agent/basic_streaming.py` | 1,380 | Streamlit App | 🟡 #10 |
| 11 | `streamlit_agent/clear_results.py` | 934 | Utility / Library | 🟢 #11 |
| 12 | `streamlit_agent/__init__.py` | 0 | Package Init | 🟢 N/A |
| 13 | `streamlit_agent/callbacks/__init__.py` | 0 | Package Init | 🟢 N/A |

**Data/Binary Assets (not Python):**
| File | Size | Note |
|---|---|---|
| `streamlit_agent/Chinook.db` | 913,408 bytes | SQLite sample database (music catalog) |
| `streamlit_agent/runs/alanis.pickle` | 138,141 bytes | Serialized LangChain callback session |
| `streamlit_agent/runs/leo.pickle` | 81,841 bytes | Serialized LangChain callback session |

**Total Python modules: 11 (2 empty init files, 9 app modules, 1 utility app, 1 utility library)**

> NOTE: The codebase has only 11 unique Python modules. All 11 are analyzed in depth below. The "TOP 20" requirement exceeds the available module count; all available modules are covered completely.

---

## 2. TOP RISK MODULES — In-Depth Analysis

---

### RANK #1 — `chat_pandas_df.py`
**Path:** `streamlit_agent/chat_pandas_df.py`
**Size:** 2,745 bytes | **Lines:** ~84
**Risk Level:** 🔴 CRITICAL

**Purpose:**
Streamlit chat application that accepts user-uploaded CSV/Excel files and creates a LangChain PandasDataFrame agent that can answer questions about the data. The agent uses `PythonAstREPLTool` to execute LLM-generated Python code against the DataFrame.

**Key Functions/Code Blocks:**

```python
# Lines 27-34: File loading with unsafe exception handling
@st.cache_data(ttl="2h")
def load_data(uploaded_file):
    try:
        ext = os.path.splitext(uploaded_file.name)[1][1:].lower()
    except:
        ext = uploaded_file.split(".")[-1]   # bare except — swallows all errors
    if ext in file_formats:
        return file_formats[ext](uploaded_file)
    else:
        st.error(f"Unsupported file format: {ext}")
        return None
```

```python
# Lines 70-75: Agent creation with OPENAI_FUNCTIONS agent type
pandas_df_agent = create_pandas_dataframe_agent(
    llm,
    df,
    verbose=True,
    agent_type=AgentType.OPENAI_FUNCTIONS,
    handle_parsing_errors=True,
)
```

```python
# Lines 77-80: Agent execution — user messages passed directly
response = pandas_df_agent.run(st.session_state.messages, callbacks=[st_cb])
```

**Security Findings:**
- **VUL-01 (CRITICAL):** `create_pandas_dataframe_agent` internally uses `PythonAstREPLTool`, which calls `exec()` on LLM-generated Python code. The entire server process is compromised if the LLM generates malicious code, is prompt-injected, or an adversary crafts a malicious DataFrame that triggers code generation.
- **VUL-11 (LOW):** Bare `except:` on line 30 silently swallows parse/IO errors.
- **VUL-FILE-01 (MEDIUM):** `uploaded_file.name` (user-controlled) used for extension extraction without sanitization. A file named `../../etc/passwd.csv` would extract `csv` as extension (benign result), but the name is used as-is.
- App itself displays a warning: "This app uses LangChain's `PythonAstREPLTool` which is vulnerable to arbitrary code execution" (lines 47-49) — confirming the RCE risk is known.

**Imports Used:** `langchain.agents.AgentType`, `langchain_experimental.agents.create_pandas_dataframe_agent`, `langchain.callbacks.StreamlitCallbackHandler`, `langchain.chat_models.ChatOpenAI`, `streamlit`, `pandas`, `os`

---

### RANK #2 — `chat_with_sql_db.py`
**Path:** `streamlit_agent/chat_with_sql_db.py`
**Size:** 3,068 bytes | **Lines:** ~79
**Risk Level:** 🔴 HIGH

**Purpose:**
Streamlit chat application enabling conversation with a SQL database. Users can either use the bundled Chinook.db or provide an arbitrary database URI.

**Key Functions/Code Blocks:**

```python
# Lines 23-29: User supplies arbitrary DB URI
radio_opt = ["Use sample database - Chinook.db", "Connect to your SQL database"]
selected_opt = st.sidebar.radio(label="Choose suitable option", options=radio_opt)
if radio_opt.index(selected_opt) == 1:
    st.sidebar.warning(INJECTION_WARNING, icon="⚠️")
    db_uri = st.sidebar.text_input(
        label="Database URI", placeholder="mysql://user:pass@hostname:port/db"
    )
```

```python
# Lines 48-55: configure_db — URI passed directly to SQLAlchemy
@st.cache_resource(ttl="2h")
def configure_db(db_uri):
    if db_uri == LOCALDB:
        db_filepath = (Path(__file__).parent / "Chinook.db").absolute()
        creator = lambda: sqlite3.connect(f"file:{db_filepath}?mode=ro", uri=True)
        return SQLDatabase(create_engine("sqlite:///", creator=creator))
    return SQLDatabase.from_uri(database_uri=db_uri)   # ← SSRF point
```

```python
# Lines 71-75: Agent runs LLM-generated SQL
response = agent.run(user_query, callbacks=[st_cb])
```

**Security Findings:**
- **VUL-02 (HIGH — SSRF):** `db_uri` from sidebar text input is passed directly to `SQLDatabase.from_uri()` → `sqlalchemy.create_engine()`. An attacker can specify URIs pointing to internal network databases, file-based SQLite paths outside the app, or trigger SSRF via database drivers that make network connections.
- **VUL-SQL-01 (HIGH — Prompt Injection → SQL):** The SQL agent translates user natural language to SQL. Malicious prompts can instruct the LLM to generate `DROP TABLE`, `DELETE`, or data exfiltration queries. The code warns about this (lines 15-19) but provides no mitigation beyond suggesting limited DB permissions.
- **Local mode mitigation:** When `LOCALDB` is selected, the connection is opened with `?mode=ro` (read-only) — a positive security control.
- **No URI allowlist:** Any `db_uri` format accepted — `file://`, `postgresql://`, `mysql://`, `mssql://`, etc.

---

### RANK #3 — `callbacks/capturing_callback_handler.py`
**Path:** `streamlit_agent/callbacks/capturing_callback_handler.py`
**Size:** 6,663 bytes | **Lines:** ~151
**Risk Level:** 🔴 HIGH

**Purpose:**
Captures all LangChain callbacks to a serialized session file (pickle) and provides a `playback_callbacks()` function to replay them. Supports offline demo playback without API calls.

**Key Functions/Code Blocks:**

```python
# Lines 42-47: Pickle deserialization — no validation
def load_records_from_file(path: str) -> list[CallbackRecord]:
    """Load the list of CallbackRecords from a pickle file at the given path."""
    with open(path, "rb") as file:
        records = pickle.load(file)     # ← UNSAFE DESERIALIZATION

    if not isinstance(records, list):
        raise RuntimeError(f"Bad CallbackRecord data in {path}")
    return records
```

```python
# Lines 109-117: Dump to pickle — also unsafe if path is user-controlled
def dump_records_to_file(self, path: str) -> None:
    """Write the list of CallbackRecords to a pickle file at the given path."""
    with open(path, "wb") as file:
        pickle.dump(self._records, file)
```

**Security Findings:**
- **VUL-03 (HIGH — Unsafe Pickle Deserialization):** `pickle.load()` on line 44 will execute arbitrary Python code if the pickle file has been tampered with. The `alanis.pickle` and `leo.pickle` files ship with the repository — if the repo is compromised or a dependency-confusion attack injects a malicious version, these files could execute arbitrary code on `import` or first page load.
- **Type check insufficient:** `isinstance(records, list)` check (line 46) occurs *after* deserialization — by that point, any `__reduce__`-based payload has already executed.
- **`dump_records_to_file` path is unvalidated:** If `path` is ever constructed from user input, it becomes a write-anywhere vulnerability.
- **Classes intentionally avoid custom types:** Code comment on lines 12-14 says "intentionally not an enum so that we avoid serializing a custom class with pickle" — shows awareness of pickle risks, but does not use a safer format (e.g., JSON).

**Recommendation:** Replace `pickle` with `json` or `msgpack` for session serialization. Existing `.pickle` files should be validated by hash before loading.

---

### RANK #4 — `mrkl_demo.py`
**Path:** `streamlit_agent/mrkl_demo.py`
**Size:** 4,196 bytes | **Lines:** ~116
**Risk Level:** 🟠 HIGH

**Purpose:**
Multi-tool MRKL (Modular Reasoning, Knowledge and Language) agent demo combining DuckDuckGo search, math chain, and SQL database chain. Supports pre-recorded session replay (pickle) and live LLM queries.

**Key Functions/Code Blocks:**

```python
# Lines 19-24: Saved sessions mapped to pickle files
SAVED_SESSIONS = {
    "Who is Leo DiCaprio's girlfriend? ...": "leo.pickle",
    "What is the full name of the female artist ...": "alanis.pickle",
}
```

```python
# Lines 43-46: Fallback API key — misleading
if user_openai_api_key:
    openai_api_key = user_openai_api_key
    enable_custom = True
else:
    openai_api_key = "not_supplied"   # ← misleading fallback
    enable_custom = False
```

```python
# Lines 70-73: Read-only SQLite connection — positive control
creator = lambda: sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
db = SQLDatabase(create_engine("sqlite:///", creator=creator))
```

```python
# Lines 104-108: Pickle file loaded from disk
session_path = Path(__file__).parent / "runs" / session_name
answer = playback_callbacks([st_callback], str(session_path), max_pause_time=2)
```

```python
# Line 71: hub.pull() — internet fetch at startup
react_agent = create_react_agent(llm, tools, hub.pull("hwchase17/react"))
```

**Security Findings:**
- **VUL-MRKL-01 (HIGH — Supply Chain via hub.pull):** `hub.pull("hwchase17/react")` fetches a prompt template from `api.hub.langchain.com` at every startup. A compromised or hijacked prompt template could inject malicious instructions into the agent.
- **VUL-MRKL-02 (MEDIUM — Fallback Key):** `openai_api_key = "not_supplied"` allows the LLM object to be constructed. If `OPENAI_API_KEY` is set in the environment, LangChain will silently use it even when `not_supplied` is passed.
- **VUL-03 (inherited — Pickle):** Session replay via `playback_callbacks` loads pickle files.
- **Multi-tool agent scope:** Agent has access to search, math execution, and SQL — broadest tool scope of any module.

---

### RANK #5 — `chat_with_documents.py`
**Path:** `streamlit_agent/chat_with_documents.py`
**Size:** 4,480 bytes | **Lines:** ~104
**Risk Level:** 🟠 HIGH

**Purpose:**
RAG chatbot that lets users upload PDFs and ask questions about them. Uses HuggingFace embeddings and DocArray in-memory vector store.

**Key Functions/Code Blocks:**

```python
# Lines 21-29: File upload → temp dir write
@st.cache_resource(ttl="1h")
def configure_retriever(uploaded_files):
    docs = []
    temp_dir = tempfile.TemporaryDirectory()
    for file in uploaded_files:
        temp_filepath = os.path.join(temp_dir.name, file.name)  # ← file.name not sanitized
        with open(temp_filepath, "wb") as f:
            f.write(file.getvalue())
        loader = PyPDFLoader(temp_filepath)
        docs.extend(loader.load())
```

```python
# Lines 60-64: Metadata displayed to user — source path exposed
def on_retriever_end(self, documents, **kwargs):
    for idx, doc in enumerate(documents):
        source = os.path.basename(doc.metadata["source"])
        self.status.write(f"**Document {idx} from {source}**")
        self.status.markdown(doc.page_content)
```

**Security Findings:**
- **VUL-04 (HIGH — Path Traversal):** `file.name` is user-controlled. `os.path.join(temp_dir.name, file.name)` with a `file.name` of `../../etc/passwd` (if Streamlit allows it) could traverse outside the temp directory. On most OS/Streamlit configurations, the filename is basnamed, but this is not explicitly enforced in the code.
- **VUL-DOC-01 (MEDIUM — PDF Bomb / Zip Bomb):** No file size limit or page count limit before calling `PyPDFLoader`. A maliciously crafted PDF could exhaust server memory.
- **VUL-DOC-02 (LOW — Source Metadata Disclosure):** `os.path.basename(doc.metadata["source"])` exposes internal temp directory file names to the UI.
- **Positive control:** `@st.cache_resource(ttl="1h")` limits re-processing, and `tempfile.TemporaryDirectory()` provides OS-managed cleanup.

---

### RANK #6 — `minimal_agent.py`
**Path:** `streamlit_agent/minimal_agent.py`
**Size:** 629 bytes | **Lines:** ~17
**Risk Level:** 🟠 HIGH

**Purpose:**
Minimal single-file agent with DuckDuckGo search. Notably, it **requires the `OPENAI_API_KEY` environment variable** — there is no sidebar API key input.

**Key Code:**

```python
# Lines 5-8: LLM and agent initialized at module load — before any user interaction
llm = OpenAI(temperature=0, streaming=True)
tools = load_tools(["ddg-search"])
agent = initialize_agent(
    tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, verbose=True
)
```

```python
# Line 15: Agent runs on any user prompt — no validation
response = agent.run(prompt, callbacks=[st_callback])
```

**Security Findings:**
- **VUL-05 (HIGH — Implicit Credential Use):** `OpenAI()` with no explicit `api_key` argument reads from `OPENAI_API_KEY` environment variable at module load time. If the env var is set (e.g., in production), any user who accesses the Streamlit page immediately has access to the LLM without any key prompt.
- **VUL-MIN-01 (MEDIUM — No Auth Guard):** Unlike other modules, there is no `if not openai_api_key: st.stop()` guard. The agent is always active.
- **VUL-MIN-02 (LOW — SSRF via Search):** DuckDuckGo search tool makes outbound web requests based on LLM-generated queries derived from user input. Prompt injection could cause SSRF-like behavior (forcing the LLM to search for internal hostnames).

---

### RANK #7 — `simple_feedback.py`
**Path:** `streamlit_agent/simple_feedback.py`
**Size:** 3,156 bytes | **Lines:** ~79
**Risk Level:** 🟡 MEDIUM

**Purpose:**
Conversational chain with LangSmith tracing integration and emoji-based user feedback collection. Traces are sent to `api.smith.langchain.com`.

**Key Code:**

```python
# Lines 16-17: API key from st.secrets first, then sidebar
openai_api_key = st.secrets.get("OPENAI_API_KEY")
if not openai_api_key:
    openai_api_key = st.sidebar.text_input("OpenAI API Key", type="password")
langchain_api_key = st.secrets.get("LANGCHAIN_API_KEY")
if not langchain_api_key:
    langchain_api_key = st.sidebar.text_input("LangChain API Key", type="password")
```

```python
# Lines 28-32: Client and tracer setup
langchain_endpoint = "https://api.smith.langchain.com"
client = Client(api_url=langchain_endpoint, api_key=langchain_api_key)
ls_tracer = LangChainTracer(project_name=project, client=client)
run_collector = RunCollectorCallbackHandler()
cfg["callbacks"] = [ls_tracer, run_collector]
```

```python
# Lines 64-72: Feedback submission
client.create_feedback(
    st.session_state.last_run,
    feedback["type"],
    score=scores[feedback["score"]],
    comment=feedback.get("text", None),
)
```

**Security Findings:**
- **VUL-SF-01 (MEDIUM — Data Exfiltration via Tracing):** All LLM inputs/outputs are sent to LangSmith. If users input sensitive data (PII, credentials), it is exfiltrated to a third-party service. No data classification or filtering is applied.
- **VUL-SF-02 (LOW — Hardcoded LangSmith Endpoint):** `langchain_endpoint = "https://api.smith.langchain.com"` is hardcoded. Not a direct vulnerability, but inflexible and undocumented behavior for users.
- **VUL-SF-03 (LOW — `project` input unsanitized):** The LangSmith project name from `st.sidebar.text_input("LangSmith Project")` is passed to `LangChainTracer(project_name=project)` without sanitization. Potential for project namespace injection.
- **Positive control:** Uses `st.secrets.get()` as primary key source — better than sidebar-only.

---

### RANK #8 — `search_and_chat.py`
**Path:** `streamlit_agent/search_and_chat.py`
**Size:** 2,525 bytes | **Lines:** ~59
**Risk Level:** 🟡 MEDIUM

**Purpose:**
Search-enabled chatbot with conversation memory. Uses `ConversationalChatAgent` with DuckDuckGo search tool and `ConversationBufferMemory`.

**Key Code:**

```python
# Lines 40-47: LLM and agent created per prompt (no caching)
llm = ChatOpenAI(model_name="gpt-3.5-turbo", openai_api_key=openai_api_key, streaming=True)
tools = [DuckDuckGoSearchRun(name="Search")]
chat_agent = ConversationalChatAgent.from_llm_and_tools(llm=llm, tools=tools)
executor = AgentExecutor.from_agent_and_tools(
    agent=chat_agent,
    tools=tools,
    memory=memory,
    return_intermediate_steps=True,
    handle_parsing_errors=True,
)
```

**Security Findings:**
- **VUL-SC-01 (MEDIUM — Conversation Memory Not Bounded):** `ConversationBufferMemory` accumulates all messages without any token limit. Long sessions can exceed LLM context windows or cause high token costs.
- **VUL-SC-02 (LOW — Search-driven SSRF):** DuckDuckGoSearchRun makes HTTP requests based on LLM-generated queries. A prompt-injected session could cause the agent to search for internal network addresses.
- **Positive control:** `handle_parsing_errors=True` prevents agent crash on malformed LLM output. `return_intermediate_steps=True` provides auditability of search steps.

---

### RANK #9 — `basic_memory.py`
**Path:** `streamlit_agent/basic_memory.py`
**Size:** 2,703 bytes | **Lines:** ~66
**Risk Level:** 🟡 MEDIUM-LOW

**Purpose:**
Simple LCEL chain demonstration with `StreamlitChatMessageHistory` for persistent conversation memory using Streamlit session state.

**Key Code:**

```python
# Lines 26-29: API key from st.secrets with sidebar fallback
if "openai_api_key" in st.secrets:
    openai_api_key = st.secrets.openai_api_key
else:
    openai_api_key = st.sidebar.text_input("OpenAI API Key", type="password")
```

```python
# Lines 43-48: LCEL chain composition
chain = prompt | ChatOpenAI(api_key=openai_api_key)
chain_with_history = RunnableWithMessageHistory(
    chain,
    lambda session_id: msgs,
    input_messages_key="question",
    history_messages_key="history",
)
```

**Security Findings:**
- **VUL-BM-01 (LOW — Session ID Hardcoded):** `config = {"configurable": {"session_id": "any"}}` — session_id is always `"any"`. Multiple users sharing the same Streamlit server would share conversation history, as `StreamlitChatMessageHistory` uses `st.session_state` keyed by a fixed key `"langchain_messages"`.
- **VUL-BM-02 (LOW — Message History Exposed in Expander):** `view_messages.json(st.session_state.langchain_messages)` exposes full message history in a UI expander — any observer with screen access can see all prior messages.
- **Positive control:** `st.secrets` is checked before sidebar input — better practice.
- **Uses modern LCEL (pipe operator)** — less deprecated surface than other modules.

---

### RANK #10 — `basic_streaming.py`
**Path:** `streamlit_agent/basic_streaming.py`
**Size:** 1,380 bytes | **Lines:** ~37
**Risk Level:** 🟡 LOW

**Purpose:**
Minimal streaming chat app demonstrating LangChain streaming callbacks with `StreamHandler`.

**Key Code:**

```python
# Line 17: API key only from sidebar — no st.secrets fallback
openai_api_key = st.text_input("OpenAI API Key", type="password")
```

```python
# Lines 33-35: LLM with streaming callback
stream_handler = StreamHandler(st.empty())
llm = ChatOpenAI(openai_api_key=openai_api_key, streaming=True, callbacks=[stream_handler])
response = llm.invoke(st.session_state.messages)
```

**Security Findings:**
- **VUL-BS-01 (LOW — No `st.secrets` Fallback):** API key is always shown in sidebar. If `OPENAI_API_KEY` is set in environment, it is not used — users must always enter the key manually.
- **VUL-BS-02 (LOW — No Input Guard on Message List):** `llm.invoke(st.session_state.messages)` sends the full `messages` list. If session state is manipulated (unlikely in Streamlit's architecture but theoretically possible), arbitrary content could be sent to OpenAI.
- **Positive:** Simplest and cleanest module. No agents, no tools, no complex chains. Lowest blast radius.

---

### RANK #11 — `clear_results.py`
**Path:** `streamlit_agent/clear_results.py`
**Size:** 934 bytes | **Lines:** ~29
**Risk Level:** 🟢 MINIMAL

**Purpose:**
Utility module providing `DirtyState` state machine and `with_clear_container()` helper to manage Streamlit rerun behavior after form submission. Only imported by `mrkl_demo.py`.

**Key Code:**

```python
class DirtyState:
    NOT_DIRTY = "NOT_DIRTY"
    DIRTY = "DIRTY"
    UNHANDLED_SUBMIT = "UNHANDLED_SUBMIT"

def with_clear_container(submit_clicked: bool) -> bool:
    if get_dirty_state() == DirtyState.DIRTY:
        if submit_clicked:
            set_dirty_state(DirtyState.UNHANDLED_SUBMIT)
            st.experimental_rerun()   # ← deprecated Streamlit API
        ...
```

**Security Findings:**
- **VUL-CR-01 (INFO — Deprecated API):** `st.experimental_rerun()` is deprecated in Streamlit ≥1.27; replaced by `st.rerun()`. No security impact, but will break on future Streamlit versions.
- **No external I/O, no user data processing.** Pure UI state management.
- **Lowest risk module in the codebase.**

---

## 3. Risk Ranking Summary

| Rank | Module | Primary Risk | Severity |
|---|---|---|---|
| 1 | `chat_pandas_df.py` | Arbitrary Code Execution (PythonAstREPLTool) | 🔴 CRITICAL |
| 2 | `chat_with_sql_db.py` | SSRF + Prompt→SQL Injection | 🔴 HIGH |
| 3 | `callbacks/capturing_callback_handler.py` | Unsafe Pickle Deserialization | 🔴 HIGH |
| 4 | `mrkl_demo.py` | Multi-vector: pickle replay + hub.pull supply chain + multi-tool scope | 🟠 HIGH |
| 5 | `chat_with_documents.py` | Path Traversal in filename + PDF bomb | 🟠 HIGH |
| 6 | `minimal_agent.py` | Implicit credential use + no auth guard | 🟠 HIGH |
| 7 | `simple_feedback.py` | PII exfiltration via LangSmith tracing | 🟡 MEDIUM |
| 8 | `search_and_chat.py` | Unbounded memory + search SSRF | 🟡 MEDIUM |
| 9 | `basic_memory.py` | Shared session state + history exposure | 🟡 LOW |
| 10 | `basic_streaming.py` | No secrets fallback | 🟡 LOW |
| 11 | `clear_results.py` | Deprecated API only | 🟢 MINIMAL |
