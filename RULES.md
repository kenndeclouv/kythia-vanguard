# 🚨 Kythia Vanguard - DEVELOPER & AI GUIDELINES 🚨

**READ THIS BEFORE WRITING ANY CODE FOR THIS PROJECT!**
This project uses a custom **Dynamic Autoloading Architecture**. Do NOT use standard Python package boilerplate. Follow these strict rules to ensure your module is loaded successfully.

## 1. CORE PHILOSOPHY: ZERO BOILERPLATE
- **DO NOT** modify `main.py`. The core orchestrator handles everything dynamically.
- **DO NOT** create `__init__.py` files. We use Implicit Namespace Packages.
- **DO NOT** manually import new modules into `main.py`.

## 2. HOW TO CREATE A NEW SCAN MODULE
If you are tasked to create a module named `cloud`:

### Step A: The Runner (The Brain)
1. Create a new file in `src/modules/` (e.g., `src/modules/cloud.py`).
2. The main execution function **MUST** start with the exact prefix `run_` (e.g., `def run_cloud(...)`).
3. The autoloader uses `inspect.signature` to inject arguments dynamically. You can use any combination of these exact parameter names:
   - `target_url: str`
   - `hostname: str`
   - `result: ScanResult`
   - `progress` (from rich.progress)
   - `task` (from rich.progress)
4. *Example signature:* `def run_cloud(target_url: str, result: ScanResult, progress, task) -> None:`
5. Always update the progress bar using `progress.update(task, ...)` and `progress.advance(task, ...)`.

### Step B: The Data Model (The Storage)
1. Open `src/models.py`.
2. Add a new field to the `@dataclass ScanResult` to store your module's findings.
3. *Example:* `cloud_findings: list = field(default_factory=list)`

### Step C: The Display (The UI)
1. Open `src/ui/display.py`.
2. Create a display function that **MUST** start with the prefix `display_` and contain the module's key (e.g., `def display_cloud(result: ScanResult) -> None:`).
3. Use `rich` (Console, Table, Panel, Rule) to format the output beautifully.
4. Only display if the data exists (e.g., `if not result.cloud_findings: return`).

### Step D: Module Registration
1. Open `src/config.py`.
2. Add the module to the `SCAN_MODULES` list.
3. The key MUST match the filename in `src/modules/` and be present in the `display_` function name.
   *Example:* `("cloud", "Cloud & Bucket Sniper — Scan exposed AWS/S3")`

## 3. STRICT ANTI-PATTERNS (DO NOT DO THIS)
- ❌ Naming the main function `def scan_target():` -> It MUST be `def run_target():`.
- ❌ Using `print()` -> Always use `progress.console.print(Panel(...))` for mid-scan alerts or `console.print()` in the display file.
- ❌ Writing long synchronous loops -> Always use `ThreadPoolExecutor` for network I/O, and remember to use `rate_limiter.wait()` to prevent bans.