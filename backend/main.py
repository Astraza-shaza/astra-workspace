import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qsl, unquote

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
ASTRA_API_KEY = os.environ.get("ASTRA_API_KEY", "")
AUTHORIZED_USER_ID = os.environ.get("AUTHORIZED_USER_ID", "")
DATABASE_PATH = os.environ.get("DATABASE_PATH", "workspace.db")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS todos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            priority    TEXT DEFAULT 'medium',
            status      TEXT DEFAULT 'pending',
            due_date    TEXT,
            created_at  TEXT,
            completed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS goals (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            description TEXT,
            status      TEXT DEFAULT 'active',
            priority    TEXT DEFAULT 'medium',
            milestones  TEXT DEFAULT '[]',
            created_at  TEXT,
            updated_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            content     TEXT DEFAULT '',
            pinned      INTEGER DEFAULT 0,
            created_at  TEXT,
            updated_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS pins (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            content     TEXT NOT NULL,
            category    TEXT DEFAULT 'note',
            source      TEXT DEFAULT 'manual',
            created_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS schedule (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            description TEXT,
            datetime    TEXT NOT NULL,
            type        TEXT DEFAULT 'event',
            status      TEXT DEFAULT 'pending',
            created_at  TEXT
        );
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _validate_telegram_init_data(init_data_raw: str) -> str:
    try:
        params = dict(parse_qsl(unquote(init_data_raw), keep_blank_values=True))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid initData format")

    received_hash = params.pop("hash", None)
    if not received_hash:
        raise HTTPException(status_code=401, detail="Missing hash in initData")

    data_check_string = "\n".join(
        f"{k}={v}" for k, v in sorted(params.items())
    )

    secret_key = hmac.new(
        b"WebAppData",
        TELEGRAM_BOT_TOKEN.encode(),
        hashlib.sha256,
    ).digest()

    expected_hash = hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_hash, received_hash):
        raise HTTPException(status_code=401, detail="Invalid Telegram signature")

    user_json = params.get("user", "{}")
    try:
        user = json.loads(user_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=401, detail="Invalid user field in initData")

    user_id = str(user.get("id", ""))
    if not user_id:
        raise HTTPException(status_code=401, detail="No user id in initData")

    return user_id


def require_auth(request: Request) -> None:
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("X-API-Key", "")

    if api_key_header:
        if not ASTRA_API_KEY:
            raise HTTPException(status_code=503, detail="API key auth not configured")
        if not hmac.compare_digest(api_key_header, ASTRA_API_KEY):
            raise HTTPException(status_code=401, detail="Invalid API key")
        return

    if auth_header.startswith("tg "):
        init_data_raw = auth_header[3:]
        if not TELEGRAM_BOT_TOKEN:
            raise HTTPException(status_code=503, detail="Telegram auth not configured")
        if not AUTHORIZED_USER_ID:
            raise HTTPException(status_code=503, detail="AUTHORIZED_USER_ID not configured")
        user_id = _validate_telegram_init_data(init_data_raw)
        if user_id != AUTHORIZED_USER_ID:
            raise HTTPException(status_code=403, detail="User not authorized")
        return

    raise HTTPException(status_code=401, detail="Authentication required")


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Astra Workspace API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class TodoCreate(BaseModel):
    title: str
    priority: Optional[str] = "medium"
    due_date: Optional[str] = None

class TodoUpdate(BaseModel):
    title: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    due_date: Optional[str] = None

class GoalCreate(BaseModel):
    title: str
    description: Optional[str] = None
    priority: Optional[str] = "medium"
    milestones: Optional[list] = []

class GoalUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None

class MilestoneUpdate(BaseModel):
    done: bool

class NoteCreate(BaseModel):
    title: str
    content: Optional[str] = ""
    pinned: Optional[bool] = False

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    pinned: Optional[bool] = None

class PinCreate(BaseModel):
    content: str
    category: Optional[str] = "note"
    source: Optional[str] = "manual"

class ScheduleCreate(BaseModel):
    title: str
    description: Optional[str] = None
    datetime: str
    type: Optional[str] = "event"

class ScheduleUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    datetime: Optional[str] = None
    status: Optional[str] = None


# ---------------------------------------------------------------------------
# Todos
# ---------------------------------------------------------------------------

@app.get("/api/todos", dependencies=[Depends(require_auth)])
def list_todos():
    conn = get_db()
    rows = conn.execute("SELECT * FROM todos").fetchall()
    conn.close()
    items = [dict(r) for r in rows]
    items.sort(key=lambda x: (PRIORITY_ORDER.get(x["priority"], 1), x["created_at"] or ""))
    return items

@app.post("/api/todos", status_code=201, dependencies=[Depends(require_auth)])
def create_todo(body: TodoCreate):
    ts = now_iso()
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO todos (title, priority, due_date, created_at) VALUES (?, ?, ?, ?)",
        (body.title, body.priority or "medium", body.due_date, ts),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)

@app.patch("/api/todos/{todo_id}", dependencies=[Depends(require_auth)])
def update_todo(todo_id: int, body: TodoUpdate):
    conn = get_db()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Todo not found")
    fields = {}
    if body.title is not None:
        fields["title"] = body.title
    if body.priority is not None:
        fields["priority"] = body.priority
    if body.due_date is not None:
        fields["due_date"] = body.due_date
    if body.status is not None:
        fields["status"] = body.status
        if body.status == "completed" and row["status"] != "completed":
            fields["completed_at"] = now_iso()
        elif body.status != "completed":
            fields["completed_at"] = None
    if fields:
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE todos SET {set_clause} WHERE id = ?", (*fields.values(), todo_id))
        conn.commit()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    conn.close()
    return dict(row)

@app.delete("/api/todos/{todo_id}", status_code=204, dependencies=[Depends(require_auth)])
def delete_todo(todo_id: int):
    conn = get_db()
    result = conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    conn.commit()
    conn.close()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Todo not found")


# ---------------------------------------------------------------------------
# Goals
# ---------------------------------------------------------------------------

@app.get("/api/goals", dependencies=[Depends(require_auth)])
def list_goals():
    conn = get_db()
    rows = conn.execute("SELECT * FROM goals ORDER BY created_at DESC").fetchall()
    conn.close()
    items = []
    for r in rows:
        item = dict(r)
        try:
            item["milestones"] = json.loads(item["milestones"] or "[]")
        except Exception:
            item["milestones"] = []
        items.append(item)
    return items

@app.post("/api/goals", status_code=201, dependencies=[Depends(require_auth)])
def create_goal(body: GoalCreate):
    ts = now_iso()
    milestones_json = json.dumps(body.milestones or [])
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO goals (title, description, priority, milestones, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (body.title, body.description, body.priority or "medium", milestones_json, ts, ts),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM goals WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    item = dict(row)
    item["milestones"] = json.loads(item["milestones"] or "[]")
    return item

@app.patch("/api/goals/{goal_id}", dependencies=[Depends(require_auth)])
def update_goal(goal_id: int, body: GoalUpdate):
    conn = get_db()
    row = conn.execute("SELECT * FROM goals WHERE id = ?", (goal_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Goal not found")
    fields: dict = {"updated_at": now_iso()}
    if body.title is not None:
        fields["title"] = body.title
    if body.description is not None:
        fields["description"] = body.description
    if body.status is not None:
        fields["status"] = body.status
    if body.priority is not None:
        fields["priority"] = body.priority
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE goals SET {set_clause} WHERE id = ?", (*fields.values(), goal_id))
    conn.commit()
    row = conn.execute("SELECT * FROM goals WHERE id = ?", (goal_id,)).fetchone()
    conn.close()
    item = dict(row)
    item["milestones"] = json.loads(item["milestones"] or "[]")
    return item

@app.patch("/api/goals/{goal_id}/milestones/{idx}", dependencies=[Depends(require_auth)])
def update_milestone(goal_id: int, idx: int, body: MilestoneUpdate):
    conn = get_db()
    row = conn.execute("SELECT * FROM goals WHERE id = ?", (goal_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Goal not found")
    try:
        milestones = json.loads(row["milestones"] or "[]")
    except Exception:
        milestones = []
    if idx < 0 or idx >= len(milestones):
        conn.close()
        raise HTTPException(status_code=404, detail="Milestone index out of range")
    milestones[idx]["done"] = body.done
    conn.execute(
        "UPDATE goals SET milestones = ?, updated_at = ? WHERE id = ?",
        (json.dumps(milestones), now_iso(), goal_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM goals WHERE id = ?", (goal_id,)).fetchone()
    conn.close()
    item = dict(row)
    item["milestones"] = json.loads(item["milestones"] or "[]")
    return item

@app.delete("/api/goals/{goal_id}", status_code=204, dependencies=[Depends(require_auth)])
def delete_goal(goal_id: int):
    conn = get_db()
    result = conn.execute("DELETE FROM goals WHERE id = ?", (goal_id,))
    conn.commit()
    conn.close()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Goal not found")


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

@app.get("/api/notes", dependencies=[Depends(require_auth)])
def list_notes():
    conn = get_db()
    rows = conn.execute("SELECT * FROM notes ORDER BY pinned DESC, updated_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/notes", status_code=201, dependencies=[Depends(require_auth)])
def create_note(body: NoteCreate):
    ts = now_iso()
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO notes (title, content, pinned, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (body.title, body.content or "", 1 if body.pinned else 0, ts, ts),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)

@app.patch("/api/notes/{note_id}", dependencies=[Depends(require_auth)])
def update_note(note_id: int, body: NoteUpdate):
    conn = get_db()
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Note not found")
    fields: dict = {"updated_at": now_iso()}
    if body.title is not None:
        fields["title"] = body.title
    if body.content is not None:
        fields["content"] = body.content
    if body.pinned is not None:
        fields["pinned"] = 1 if body.pinned else 0
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE notes SET {set_clause} WHERE id = ?", (*fields.values(), note_id))
    conn.commit()
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    return dict(row)

@app.delete("/api/notes/{note_id}", status_code=204, dependencies=[Depends(require_auth)])
def delete_note(note_id: int):
    conn = get_db()
    result = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Note not found")


# ---------------------------------------------------------------------------
# Pins
# ---------------------------------------------------------------------------

@app.get("/api/pins", dependencies=[Depends(require_auth)])
def list_pins(category: Optional[str] = Query(default=None)):
    conn = get_db()
    if category:
        rows = conn.execute("SELECT * FROM pins WHERE category = ? ORDER BY created_at DESC", (category,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM pins ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/pins", status_code=201, dependencies=[Depends(require_auth)])
def create_pin(body: PinCreate):
    ts = now_iso()
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO pins (content, category, source, created_at) VALUES (?, ?, ?, ?)",
        (body.content, body.category or "note", body.source or "manual", ts),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM pins WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)

@app.delete("/api/pins/{pin_id}", status_code=204, dependencies=[Depends(require_auth)])
def delete_pin(pin_id: int):
    conn = get_db()
    result = conn.execute("DELETE FROM pins WHERE id = ?", (pin_id,))
    conn.commit()
    conn.close()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Pin not found")


# ---------------------------------------------------------------------------
# Schedule
# ---------------------------------------------------------------------------

@app.get("/api/schedule", dependencies=[Depends(require_auth)])
def list_schedule():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    conn = get_db()
    rows = conn.execute("SELECT * FROM schedule WHERE datetime >= ? ORDER BY datetime ASC", (today,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/schedule", status_code=201, dependencies=[Depends(require_auth)])
def create_event(body: ScheduleCreate):
    ts = now_iso()
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO schedule (title, description, datetime, type, created_at) VALUES (?, ?, ?, ?, ?)",
        (body.title, body.description, body.datetime, body.type or "event", ts),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM schedule WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)

@app.patch("/api/schedule/{event_id}", dependencies=[Depends(require_auth)])
def update_event(event_id: int, body: ScheduleUpdate):
    conn = get_db()
    row = conn.execute("SELECT * FROM schedule WHERE id = ?", (event_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Event not found")
    fields = {}
    if body.title is not None:
        fields["title"] = body.title
    if body.description is not None:
        fields["description"] = body.description
    if body.datetime is not None:
        fields["datetime"] = body.datetime
    if body.status is not None:
        fields["status"] = body.status
    if fields:
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE schedule SET {set_clause} WHERE id = ?", (*fields.values(), event_id))
        conn.commit()
    row = conn.execute("SELECT * FROM schedule WHERE id = ?", (event_id,)).fetchone()
    conn.close()
    return dict(row)

@app.delete("/api/schedule/{event_id}", status_code=204, dependencies=[Depends(require_auth)])
def delete_event(event_id: int):
    conn = get_db()
    result = conn.execute("DELETE FROM schedule WHERE id = ?", (event_id,))
    conn.commit()
    conn.close()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Event not found")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/dashboard", dependencies=[Depends(require_auth)])
def dashboard():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    conn = get_db()
    goals = [dict(r) for r in conn.execute("SELECT * FROM goals").fetchall()]
    active_goals = sum(1 for g in goals if g["status"] == "active")
    total_goals = len(goals)
    goal_progress = []
    for g in goals:
        try:
            milestones = json.loads(g["milestones"] or "[]")
        except Exception:
            milestones = []
        done = sum(1 for m in milestones if m.get("done"))
        goal_progress.append({
            "id": g["id"], "title": g["title"], "done": done,
            "total": len(milestones), "priority": g["priority"], "status": g["status"],
        })
    todos = conn.execute("SELECT status FROM todos").fetchall()
    open_todos = sum(1 for t in todos if t["status"] != "completed")
    completed_todos = sum(1 for t in todos if t["status"] == "completed")
    upcoming_rows = conn.execute(
        "SELECT * FROM schedule WHERE datetime >= ? ORDER BY datetime ASC LIMIT 5", (today,)
    ).fetchall()
    upcoming_events = [dict(r) for r in upcoming_rows]
    conn.close()
    return {
        "active_goals": active_goals, "total_goals": total_goals,
        "open_todos": open_todos, "completed_todos": completed_todos,
        "goal_progress": goal_progress, "upcoming_events": upcoming_events,
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
