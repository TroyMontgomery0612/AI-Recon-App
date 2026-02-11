# Product Specification: ReconGuard (Ethical Reconnaissance Framework)
**Version:** 1.1 (PostgreSQL Enhanced)
**Type:** Penetration Testing / Educational Tool
**Status:** Architecture & Planning Phase

---

## 1. Core Philosophy & "Golden Rules" (CRITICAL)
This application is a **"Compliance-First"** reconnaissance tool. Unlike standard hacking tools, this app **technically restricts** scanning to pre-authorized scopes.

**The AI Assistant MUST adhere to these Golden Rules at all times:**

1.  **The "Kill Switch" Rule (Zero Trust Networking):**
    * **NO** network packet is allowed to leave the application without first passing through the `ScopeEnforcement` middleware.
    * If a target IP/Domain is not explicitly in the `AllowedScope` list, the request must be **dropped** and the event logged as a security violation.
    * *Technical Implementation:* A Python decorator (`@require_scope`) must wrap every single scanning function.

2.  **The "Authorization First" Rule:**
    * A "Project" cannot be initialized without a digital **Authorization Artifact** stored in the database.
    * The app must verify the existence of this artifact before enabling any "Active Recon" modules.

3.  **The "Immutable Audit" Rule:**
    * Every action must be logged to a tamper-evident audit log.
    * Logs must include: `Timestamp`, `User`, `Action`, `Target`, and `AuthorizationID`.

---

## 2. Technical Architecture & Stack

### Backend
* **Language:** Python 3.10+
* **Framework:** FastAPI (Async/Await required).
* **Database:** **PostgreSQL** (Production-grade).
    * *Connection:* Use `SQLAlchemy` with `psycopg2-binary` driver.
    * *Credentials:* Default to `kali:kali@localhost/recondb`.
* **Key Libraries:** `pydantic` (Validation), `sqlalchemy` (ORM), `dnspython` (DNS), `python-nmap` (Scanning).

### Frontend
* **Framework:** React (Vite).
* **Language:** TypeScript.
* **UI Library:** TailwindCSS + Shadcn/UI.

---

## 3. Development Phases (Step-by-Step Plan)

### Phase 1: The Legal Foundation (Scope & Safety)
**Goal:** Build the "Safety Layer" and Database Connection.
* **Task 1.1:** Configure **PostgreSQL** connection logic in `app/core/db.py`.
* **Task 1.2:** Create `TargetScope` Pydantic model and SQL Table.
* **Task 1.3:** Implement `ScopeEngine`. A class with `is_target_allowed(ip) -> bool`.
* **Task 1.4:** Create the `@require_scope` decorator.

### Phase 2: Passive Reconnaissance (OSINT)
* **Task 2.1:** DNS Enumeration Module.
* **Task 2.2:** Whois Lookup.
* **Task 2.3:** Tech Stack Detection.

### Phase 3: Active Reconnaissance (The Dangerous Part)
* **Constraint:** MUST be wrapped in `ScopeEngine`.
* **Task 3.1:** Port Scanner Wrapper (`nmap`).
* **Task 3.2:** Service Fingerprinting.

---

## 4. Specific "Do Not Do" List for AI
* **DO NOT** write code that executes system commands without sanitization.
* **DO NOT** hardcode API keys. Use `.env` files.
* **DO NOT** suggest Exploitation features. Reconnaissance only.
