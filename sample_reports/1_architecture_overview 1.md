# Architecture Overview
**Target:** `/root/streamlit-agent-main/streamlit_agent`
**Analysis Date:** February 22, 2026
**Analyst:** UC Recon — Deep Forensics Mode

---

## 1. Executive Summary

`streamlit-agent` is a **collection of 9 independent Streamlit single-page applications** that each demonstrate a distinct LangChain integration pattern. There is no shared application server, no routing layer, no authentication middleware, and no central orchestration process. Each `.py` file is both entry point and complete application. The Docker default entrypoint is `chat_pandas_df.py`, but any module can be launched independently.

The architecture is **flat and modular**: most modules are standalone pages; two (`mrkl_demo.py`) consume internal helpers from `callbacks/` and `clear_results.py`.

---

## 2. System Layers

```
┌─────────────────────────────────────────────────────────┐
│               PRESENTATION LAYER                        │
│  Streamlit UI (st.chat_input, st.sidebar, st.chat_message│
│  st.file_uploader, st.form, st.selectbox, st.expander)  │
└──────────────────────────┬──────────────────────────────┘
                           │ st.session_state / st.secrets
┌──────────────────────────▼──────────────────────────────┐
│               AGENT / CHAIN LAYER                       │
│  LangChain Agents (SQL, Pandas REPL, ConversationalChat)│
│  LangChain Chains (ConversationalRetrieval, ConvChain,  │
│    SQLDatabaseChain, LLMMathChain)                      │
│  LangChain Hub (hwchase17/react prompt pulled at runtime)│
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│               TOOL / MEMORY LAYER                       │
│  Tools: DuckDuckGoSearch, PythonAstREPLTool (implicit), │
│    SQLDatabaseToolkit, LLMMathChain (as Tool)           │
│  Memory: ConversationBufferMemory, StreamlitChatHistory  │
│  VectorStore: DocArrayInMemorySearch (in-process)       │
│  Embeddings: HuggingFaceEmbeddings (all-MiniLM-L6-v2)  │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│               MODEL LAYER                               │
│  OpenAI: ChatOpenAI (gpt-3.5-turbo, gpt-3.5-turbo-0613)│
│  OpenAI: OpenAI (text completion, temperature=0)        │
│  API keys accepted at runtime via sidebar / st.secrets  │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│               PERSISTENCE / EXTERNAL LAYER              │
│  SQLite: Chinook.db (local, read-only for local mode)   │
│  User-supplied DB URI (arbitrary RDBMS via SQLAlchemy)  │
│  Pickle files: runs/alanis.pickle, runs/leo.pickle      │
│  Temp filesystem: tempfile.TemporaryDirectory (PDFs)    │
│  LangSmith: https://api.smith.langchain.com             │
│  LangChain Hub: hub.pull() at runtime                   │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Design Patterns

| Pattern | Files Using It | Notes |
|---|---|---|
| **Streamlit Script-as-App** | All 9 modules | No `if __name__ == '__main__'` — Streamlit re-executes entire script on each interaction |
| **LangChain LCEL (pipe operator)** | `basic_memory.py` | `prompt \| ChatOpenAI(...)` chain composition |
| **Legacy LangChain Chains** | `chat_with_documents.py`, `simple_feedback.py`, `chat_with_sql_db.py`, `mrkl_demo.py` | Uses deprecated `langchain.chat_models`, `langchain.chains` |
| **AgentExecutor pattern** | `chat_pandas_df.py`, `chat_with_sql_db.py`, `search_and_chat.py`, `mrkl_demo.py`, `minimal_agent.py` | Wraps tools + LLM in autonomous loop |
| **Callback-driven streaming** | `basic_streaming.py`, `chat_with_documents.py`, `mrkl_demo.py`, `search_and_chat.py` | `BaseCallbackHandler` subclasses push tokens to UI |
| **Session-state memory** | `basic_memory.py`, `search_and_chat.py`, `simple_feedback.py`, `chat_with_documents.py` | `StreamlitChatMessageHistory` wraps `st.session_state` |
| **@st.cache_resource** | `chat_with_documents.py`, `chat_with_sql_db.py` | Expensive resources (DB, retriever) cached across reruns |
| **@st.cache_data** | `chat_pandas_df.py`, `simple_feedback.py` | Data objects cached with TTL |
| **Pickle-based session replay** | `mrkl_demo.py` + `capturing_callback_handler.py` | Saved LangChain callback streams replayed from disk |
| **RAG (Retrieval-Augmented Generation)** | `chat_with_documents.py` | PDF → chunked → embedded → in-memory vector DB → ConversationalRetrievalChain |

---

## 4. Module Relationships

```
streamlit_agent/
├── basic_memory.py            [standalone]
├── basic_streaming.py         [standalone]
├── chat_pandas_df.py          [standalone] ← Docker default
├── chat_with_documents.py     [standalone]
├── chat_with_sql_db.py        [standalone]
├── clear_results.py           [utility — imported by mrkl_demo.py]
├── minimal_agent.py           [standalone]
├── mrkl_demo.py               [imports: callbacks/capturing_callback_handler.py,
│                               clear_results.py]
├── search_and_chat.py         [standalone]
├── simple_feedback.py         [standalone]
└── callbacks/
    └── capturing_callback_handler.py  [utility — imported by mrkl_demo.py]
```

Only `mrkl_demo.py` imports internal helpers. All other modules are fully self-contained.

---

## 5. Security Posture

| Domain | Assessment |
|---|---|
| **Authentication** | ❌ NONE — no login, session tokens, or access control on any page |
| **API Key Management** | ⚠️ WEAK — keys accepted in sidebar text inputs; stored in `st.session_state`; some fall back to `st.secrets` |
| **Input Validation** | ❌ NONE — user prompts passed directly to LLM agents without sanitization |
| **SQL Injection** | ⚠️ NOTED in code comments — uses LangChain's SQL agent which is prompt-injectable |
| **Arbitrary Code Execution** | 🔴 CRITICAL — `chat_pandas_df.py` uses `PythonAstREPLTool`; code acknowledged in warning |
| **Path Traversal** | ⚠️ MEDIUM — uploaded file names used directly in `os.path.join` without sanitization |
| **SSRF** | ⚠️ MEDIUM — user-controlled DB URI passed directly to `SQLDatabase.from_uri()` |
| **Pickle Deserialization** | 🔴 HIGH — `pickle.load()` on user-reachable path in `capturing_callback_handler.py` |
| **Dependency Security** | ⚠️ MEDIUM — `langchain-experimental` included (explicitly risky per LangChain docs) |
| **External Telemetry** | ⚠️ INFO — `simple_feedback.py` sends traces + feedback to `api.smith.langchain.com` |

**Overall Posture: HIGH RISK** — This codebase was designed as demo/educational material, not production-hardened software. It has no authentication, no input sanitization, and at least two critical RCE pathways.

---

## 6. Runtime Environment

- **Python:** ≥3.10, <4.0 (Dockerfile uses 3.11)
- **Framework:** Streamlit ≥1.26
- **Package Manager:** Poetry
- **Container:** Docker (python:3.11-buster builder → python:3.11-slim-buster runtime)
- **Default Port:** 8051
- **LLM Provider:** OpenAI (API key required at runtime)
- **No environment variables baked into image** — all secrets are runtime inputs
