# Dependency Map
**Target:** `/root/streamlit-agent-main/streamlit_agent`
**Analysis Date:** February 22, 2026
**Analyst:** UC Recon — Deep Forensics Mode

---

## 1. Internal Import Graph

```
mrkl_demo.py
  └── streamlit_agent.callbacks.capturing_callback_handler  [playback_callbacks]
  └── streamlit_agent.clear_results                         [with_clear_container]

clear_results.py
  └── (no internal imports)

callbacks/capturing_callback_handler.py
  └── (no internal imports)

All other modules:
  └── (no internal imports — fully standalone)
```

**Internal coupling is minimal.** Only `mrkl_demo.py` imports siblings. All other 8 application modules are independent.

---

## 2. External Import Statements (Per Module)

### `basic_memory.py`
```python
from langchain_community.chat_message_histories import StreamlitChatMessageHistory
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_openai import ChatOpenAI
import streamlit as st
```
**Packages:** `langchain-community`, `langchain-core`, `langchain-openai`, `streamlit`

---

### `basic_streaming.py`
```python
from langchain.callbacks.base import BaseCallbackHandler
from langchain.schema import ChatMessage
from langchain_openai import ChatOpenAI
import streamlit as st
```
**Packages:** `langchain`, `langchain-openai`, `streamlit`

---

### `chat_pandas_df.py`
```python
from langchain.agents import AgentType
from langchain_experimental.agents import create_pandas_dataframe_agent
from langchain.callbacks import StreamlitCallbackHandler
from langchain.chat_models import ChatOpenAI
import streamlit as st
import pandas as pd
import os
```
**Packages:** `langchain`, `langchain-experimental`, `streamlit`, `pandas`, stdlib `os`

---

### `chat_with_documents.py`
```python
import os
import tempfile
import streamlit as st
from langchain.chat_models import ChatOpenAI
from langchain.document_loaders import PyPDFLoader
from langchain.memory import ConversationBufferMemory
from langchain.memory.chat_message_histories import StreamlitChatMessageHistory
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.callbacks.base import BaseCallbackHandler
from langchain.chains import ConversationalRetrievalChain
from langchain.vectorstores import DocArrayInMemorySearch
from langchain.text_splitter import RecursiveCharacterTextSplitter
```
**Packages:** `langchain`, `langchain-community` (via langchain shim), `pypdf`, `sentence-transformers`, `docarray`, `hnswlib`, `streamlit`, stdlib `os`, `tempfile`

---

### `chat_with_sql_db.py`
```python
import streamlit as st
from pathlib import Path
from langchain.llms.openai import OpenAI
from langchain.agents import create_sql_agent
from langchain.sql_database import SQLDatabase
from langchain.agents.agent_types import AgentType
from langchain.callbacks import StreamlitCallbackHandler
from langchain.agents.agent_toolkits import SQLDatabaseToolkit
from sqlalchemy import create_engine
import sqlite3
```
**Packages:** `langchain`, `sqlalchemy`, `streamlit`, stdlib `pathlib`, `sqlite3`

---

### `clear_results.py`
```python
import streamlit as st
```
**Packages:** `streamlit`

---

### `minimal_agent.py`
```python
from langchain.llms import OpenAI
from langchain.agents import AgentType, initialize_agent, load_tools
from langchain.callbacks import StreamlitCallbackHandler
import streamlit as st
```
**Packages:** `langchain`, `duckduckgo-search` (via `load_tools(["ddg-search"])`), `streamlit`

---

### `mrkl_demo.py`
```python
from pathlib import Path
import streamlit as st
from langchain import hub
from langchain.agents import AgentExecutor, Tool, create_react_agent
from langchain.chains import LLMMathChain
from langchain_community.callbacks import StreamlitCallbackHandler
from langchain_community.utilities import DuckDuckGoSearchAPIWrapper, SQLDatabase
from langchain_core.runnables import RunnableConfig
from langchain_experimental.sql import SQLDatabaseChain
from langchain_openai import OpenAI
from sqlalchemy import create_engine
import sqlite3
from streamlit_agent.callbacks.capturing_callback_handler import playback_callbacks
from streamlit_agent.clear_results import with_clear_container
```
**Packages:** `langchain`, `langchain-community`, `langchain-core`, `langchain-experimental`, `langchain-openai`, `langchainhub`, `sqlalchemy`, `streamlit`, stdlib `pathlib`, `sqlite3`

---

### `search_and_chat.py`
```python
from langchain.agents import ConversationalChatAgent, AgentExecutor
from langchain.memory import ConversationBufferMemory
from langchain_community.callbacks import StreamlitCallbackHandler
from langchain_community.chat_message_histories import StreamlitChatMessageHistory
from langchain_community.tools import DuckDuckGoSearchRun
from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI
import streamlit as st
```
**Packages:** `langchain`, `langchain-community`, `langchain-core`, `langchain-openai`, `duckduckgo-search`, `streamlit`

---

### `simple_feedback.py`
```python
from langchain.chains import ConversationChain
from langchain.memory import ConversationBufferMemory
from langchain_community.chat_message_histories import StreamlitChatMessageHistory
from langchain_core.runnables import RunnableConfig
from langchain_core.tracers import LangChainTracer
from langchain_core.tracers.run_collector import RunCollectorCallbackHandler
from langchain_openai import OpenAI
from langsmith import Client
import streamlit as st
from streamlit_feedback import streamlit_feedback
import time
```
**Packages:** `langchain`, `langchain-community`, `langchain-core`, `langchain-openai`, `langsmith`, `streamlit-feedback`, `streamlit`, stdlib `time`

---

### `callbacks/capturing_callback_handler.py`
```python
from __future__ import annotations
import pickle
import time
from typing import Any, TypedDict
from langchain.callbacks.base import BaseCallbackHandler
```
**Packages:** `langchain`, stdlib `pickle`, `time`, `typing`

---

## 3. Consolidated Package → Module Matrix

| PyPI Package | Modules Using It | Risk Level |
|---|---|---|
| `streamlit` | ALL 9 + clear_results | LOW |
| `langchain` | ALL 9 + capturing_callback_handler | MEDIUM (deprecated imports) |
| `langchain-community` | basic_memory, mrkl_demo, search_and_chat, simple_feedback | LOW |
| `langchain-core` | basic_memory, mrkl_demo, search_and_chat, simple_feedback | LOW |
| `langchain-openai` | basic_memory, basic_streaming, mrkl_demo, search_and_chat, simple_feedback | LOW |
| `langchain-experimental` | chat_pandas_df, mrkl_demo | 🔴 HIGH — explicitly risky, contains `PythonAstREPLTool` |
| `openai` | (transitive via langchain-openai) | MEDIUM |
| `langchainhub` | mrkl_demo | MEDIUM — pulls prompts from internet at runtime |
| `langsmith` | simple_feedback | MEDIUM — telemetry/tracing to external service |
| `streamlit-feedback` | simple_feedback | LOW |
| `pandas` | chat_pandas_df | LOW |
| `sqlalchemy` | chat_with_sql_db, mrkl_demo | MEDIUM |
| `duckduckgo-search` | minimal_agent, search_and_chat, mrkl_demo | LOW |
| `pypdf` | chat_with_documents | LOW |
| `sentence-transformers` | chat_with_documents | MEDIUM (large, network-trained model) |
| `torch` | chat_with_documents (transitive) | LOW |
| `docarray` | chat_with_documents | LOW |
| `hnswlib` | chat_with_documents | LOW |
| `numexpr` | chat_with_documents (transitive math) | LOW |
| `tabulate` | (declared, not directly observed in source) | LOW |
| stdlib `pickle` | capturing_callback_handler | 🔴 HIGH — deserialization risk |
| stdlib `sqlite3` | chat_with_sql_db, mrkl_demo | MEDIUM |
| stdlib `os`, `tempfile`, `pathlib`, `time` | various | LOW |

---

## 4. Coupling Analysis

### Afferent Coupling (who depends on whom)
- `clear_results.py` ← `mrkl_demo.py` (1 consumer)
- `callbacks/capturing_callback_handler.py` ← `mrkl_demo.py` (1 consumer)
- All other modules: **0 internal consumers** (maximally decoupled)

### Efferent Coupling (what each module depends on)
- Most complex: `mrkl_demo.py` — imports from 5 langchain namespaces + 2 internal modules + sqlalchemy + sqlite3
- Most minimal: `clear_results.py` — imports only `streamlit`

### Coupling Risk
- **Extremely low internal coupling** — a positive characteristic for a demo suite
- **High external coupling** on `langchain` ecosystem — version pinning is critical; the deprecated `langchain.chat_models`, `langchain.llms`, `langchain.memory`, etc. will break on future major LangChain releases
- **`langchain-experimental` coupling is critical risk** — this package contains tools explicitly marked as unsafe for production

---

## 5. Version & Dependency Risk Summary

| Risk | Detail |
|---|---|
| **Deprecated API usage** | `langchain.chat_models.ChatOpenAI`, `langchain.llms.openai.OpenAI`, `langchain.memory`, `langchain.embeddings`, `langchain.vectorstores`, `langchain.document_loaders`, `langchain.chains` — all of these are now in `langchain-community` or `langchain-core`; the old shim paths are deprecated |
| **No upper version pins on langchain** | `langchain = {version = ">=0.1.0"}` — any breaking 1.x release could break all modules |
| **langchain-experimental is explicitly dangerous** | Per LangChain docs: "langchain-experimental contains code that is experimental in nature… may be security-relevant" |
| **Runtime internet access** | `hub.pull("hwchase17/react")` in `mrkl_demo.py` fetches prompt templates from `api.hub.langchain.com` at startup; supply-chain risk |
| **Pickle files shipped in repo** | `runs/alanis.pickle`, `runs/leo.pickle` — if tampered, arbitrary code executes on `pickle.load()` |
