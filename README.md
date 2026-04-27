```text
╭─────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                     │
│        ██╗  ██╗███████╗███╗   ██╗███╗   ██╗      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗        │
│        ██║ ██╔╝██╔════╝████╗  ██║████╗  ██║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║        │
│        █████╔╝ █████╗  ██╔██╗ ██║██╔██╗ ██║█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║        │
│        ██╔═██╗ ██╔══╝  ██║╚██╗██║██║╚██╗██║╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║        │
│        ██║  ██╗███████╗██║ ╚████║██║ ╚████║      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║        │
│        ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═══╝      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝        │
│                                        ╔═══╗ ╦═╗ ╔═╗                                                │
│                                        ╠═══╝ ╠╦╝ ║ ║                                                │
│                                        ╩     ╩╚═ ╚═╝                                                │
│       Author  : Kenndeclouv                                                                         │
│       Github  : https://github.com/kenndeclouv                                                      │
│       Website : https://kenndeclouv.com                                                             │
│       Version : 1.0.0-rc.1                                                                          │
│                                                                                                     │
╰────────────────────── For authorized security testing only — use responsibly ───────────────────────╯
```

**Advanced Automated Reconnaissance & Security Auditor**

KENN-RECON Pro is a modular, high-performance, and visually stunning CLI tool designed for automated web application reconnaissance and security auditing. Built with a dynamic autoloading architecture, it seamlessly integrates custom Python modules and powerful third-party engines like `nuclei` to deliver comprehensive security reports directly to your terminal.

> [!WARNING]
> **LEGAL DISCLAIMER**
> 
> This tool is intended EXCLUSIVELY for authorized security testing, bug-bounty programs, and penetration tests where explicit written permission has been granted. The authors accept NO liability for misuse.

---

## ✨ Key Features
* **Dynamic Autoloading Architecture:** Zero boilerplate! Add or remove modules simply by editing `src/config.py`. The core engine automatically parses your modules, resolves dependencies, and injects parameters.
* **Badass Terminal UI (TUI):** Built with `rich` and `prompt_toolkit`. Features interactive menus, live multi-progress bars, color-coded tables, and animated panels.
* **Nuclei Wrapper Integration:** Unleash the full power of ProjectDiscovery's `nuclei` directly within the TUI. Results are automatically parsed, summarized, and formatted.
* **Smart Fuzzing & Deep Crawling:** Multi-threaded directory fuzzing and recursive spidering to map out sitemaps, JS endpoints, and hidden parameters.
* **Comprehensive Export:** Automatically generates detailed `JSON` and `Markdown` reports in the `reports/` directory after every scan.

---

## 🛠️ Installation & Setup

### 1. Python Environment Setup
Due to PEP 668 on modern Linux distributions (like Pop!_OS, Ubuntu), it is highly recommended to run this tool inside a virtual environment.

```bash
# Clone the repository
git clone [https://github.com/kenndeclouv/kenn-recon-pro.git](https://github.com/kenndeclouv/kenn-recon-pro.git)
cd kenn-recon-pro

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 2. External Dependencies (Nuclei)
To utilize the powerful Vulnerability Scanner module, you must have `nuclei` installed on your system.

```bash
# Install Go (if not installed)
sudo apt install golang

# Install Nuclei
go install -v [github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest](https://github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)

# Add Go bin to your PATH (add this to your .bashrc or .zshrc)
export PATH=$PATH:$HOME/go/bin

# Update Nuclei templates
nuclei -update-templates
```

### 3. Wordlist Setup (For Fuzzing)
Download a wordlist and place it in the root directory (e.g., `words.txt` or `raft-small-words.txt`) for the fuzzing module to use.

---

## 💻 Usage

Make sure you are in your virtual environment (`source venv/bin/activate`).

**Interactive Mode (Recommended)**
Provides a beautiful UI to select target, configure scan speed, and toggle specific modules.

```bash
python main.py
```

**Quick CLI Mode**
For automation and scripting.

```bash
# Run all default modules
python main.py quick example.com

# Run specific modules with brutal speed (100 req/s)
python main.py quick example.com -m recon,waf,nuclei --rps 100
```

---

## 📂 Project Structure

```text
├── main.py                 # Core orchestrator and dynamic autoloader
├── requirements.txt        # Python dependencies
├── words.txt              # Fuzzing dictionary
├── reports/                # Generated JSON and Markdown scan reports
└── src/
    ├── config.py           # Globals, API keys, and Module Registry
    ├── models.py           # Data structures (ScanResult)
    ├── export.py           # Report generation logic
    ├── scoring.py          # Security posture grading logic
    ├── ui/                 # UI components (Banner, Menu, Display logic)
    └── modules/            # The Brains: Drop new .py modules here
        ├── recon.py
        ├── waf.py
        ├── fuzzing.py
        ├── spider.py
        ├── nuclei.py       # Wrapper for the Nuclei engine
        └── ...
```

---

## ⚙️ Developer Guide: How to Add a New Module

KENN-RECON Pro uses a powerful **Self-Contained Plugin Architecture** with dynamic autoloading. You **do not** need to edit `main.py` or mess with complex boilerplate to add new features!

Everything from the scanning logic to the UI rendering lives cleanly inside a single file in the `src/modules/` directory.
For strict instructions on how to write, format, and register new modules so they seamlessly integrate with the Autoloader and Terminal UI, please read the [Developer Guidelines (RULES.md)](RULES.md).

---

- **Author:** Kenndeclouv ([Kenndeclouv Tech](https://kenndeclouv.com))
- **License:** MIT
