# 🚨 Kythia Vanguard - DEVELOPER & AI GUIDELINES 🚨

**READ THIS BEFORE WRITING ANY CODE FOR THIS PROJECT!**
This project uses a custom **Self-Contained Plugin Architecture** with Dynamic Autoloading. Do NOT use standard Python package boilerplate. Follow these strict rules to ensure your module is loaded successfully.

## 1. CORE PHILOSOPHY: ZERO BOILERPLATE & SELF-CONTAINED
- **DO NOT** modify `main.py`. The core orchestrator handles everything dynamically.
- **DO NOT** create `__init__.py` files. We use Implicit Namespace Packages.
- **DO NOT** modify `src/ui/display.py` for new modules. The UI logic must live inside the module file itself.

## 2. HOW TO CREATE A NEW SCAN MODULE
If you are tasked to create a module named `cloud`:

### Step A: The Runner & Display (The Brain & The UI)
1. Create ONE new file in `src/modules/` (e.g., `src/modules/cloud.py`).
2. **The Runner:** The main execution function **MUST** start with the exact prefix `run_` (e.g., `def run_cloud(...)`).
   - The autoloader uses `inspect.signature` to inject arguments dynamically. Use any combination of: `target_url: str`, `hostname: str`, `result: ScanResult`, `progress`, `task`.
   - *Example:* `def run_cloud(target_url: str, result: ScanResult, progress, task) -> None:`
   - Always update the progress bar using `progress.update(task, ...)` and `progress.advance(task, ...)`.
3. **The Display:** In the **SAME FILE**, create a display function that **MUST** start with the prefix `display_` (e.g., `def display_cloud(result: ScanResult) -> None:`).
   - Use `rich` (Console, Table, Panel, Rule) to format the output beautifully.
   - Only display if the data exists (e.g., `if not result.cloud_findings: return`).

### Step B: The Data Model (The Storage)
1. Open `src/models.py`.
2. Add a new field to the `@dataclass ScanResult` to store your module's findings.
3. *Example:* `cloud_findings: list = field(default_factory=list)`

### Step C: Module Registration
1. Open `src/config.py`.
2. Add the module to the `SCAN_MODULES` list.
3. The key MUST match the filename in `src/modules/`.
   *Example:* `("cloud", "Cloud & Bucket Sniper — Scan exposed AWS/S3")`

## 3. STRICT ANTI-PATTERNS (DO NOT DO THIS)
- ❌ Naming the main function `def scan_target():` -> It MUST be `def run_target():`.
- ❌ Putting the display function in `src/ui/display.py` -> It MUST be in your module file.
- ❌ Using `print()` -> Always use `progress.console.print(Panel(...))` for mid-scan alerts or `console.print()` in the display file.
- ❌ Writing long synchronous loops -> Always use `ThreadPoolExecutor` for network I/O, and remember to use `rate_limiter.wait()` to prevent bans.