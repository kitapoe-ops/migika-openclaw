# Magika + Brave + OpenClaw Integration

**AI-Powered Pre-Execution Security Scanner for OpenClaw**

This project integrates Google Magika (AI file type detection) with Brave Search API and Felo AI to provide intelligent security scanning before executing commands in OpenClaw.

## Features

- **Magika AI Scanner**: Uses Google's deep learning model to identify file content types with 99% accuracy (200+ file types)
- **Brave Search API**: Real-time threat intelligence lookup for suspicious files
- **Felo AI Research**: Deep multi-source analysis for security research
- **Risk Classification**: Automatic risk level assessment (LOW/MEDIUM/HIGH)
- **Execution Control**: BLOCK high-risk files, require approval for medium-risk, auto-execute low-risk

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  User Command: python download.py                            │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Extract file paths from command                    │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Magika AI Scan (Python)                           │
│           → Analyzes actual file content                   │
│           → 99% accuracy, 200+ file types                 │
│           → Identifies binary disguised as scripts          │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Step 3: Risk Classification                               │
│           HIGH: Binary + script extension = BLOCK           │
│           MEDIUM: Unknown type = Brave + Felo research     │
│           LOW: Verified script = Execute                   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Step 4: Security Research (MEDIUM/HIGH only)               │
│           Brave: Quick threat intel search                  │
│           Felo: Deep AI research (15-40 sources)           │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Step 5: Execution Decision                                │
│           🚫 BLOCK / ⚠️ APPROVAL / ✅ ALLOW              │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.8+ with Magika installed
- Node.js 18+
- Brave Search API key
- Felo AI API key (optional, for deep research)

### Installation

1. **Install Magika**
```bash
pip install magika
```

2. **Configure API Keys**
```bash
# Set environment variables
export BRAVE_API_KEY="your-brave-api-key"
export FELO_API_KEY="your-felo-api-key"  # Optional
```

3. **Run the Scanner**
```bash
# Scan a command before execution
node magika_brave_exec.cjs "python script.py"

# Auto-execute without confirmation
node magika_brave_exec.cjs "python script.py" --auto
```

## Usage

### Command Line

```bash
# Basic scan
node magika_brave_exec.cjs "python download.py"

# With auto-execution (skip confirmation)
node magika_brave_exec.cjs "python download.py" --auto

# PowerShell
node magika_brave_exec.cjs "powershell script.ps1"
```

### Python Scanner Only

```bash
# Just Magika scan (no Brave/Felo)
python magika_exec_scanner.py "python script.py"

# Exit codes:
# 0 = ALLOW (safe)
# 1 = WARN (review needed)
# 2 = BLOCK (dangerous)
# 3 = ERROR
```

## Risk Levels

| Level | Condition | Action |
|-------|-----------|--------|
| 🟢 LOW | File content matches extension, verified script | Auto-execute |
| 🟡 MEDIUM | Unknown file type or potential issue | Brave+Felo research, require confirmation |
| 🚫 HIGH | Binary content detected with script extension | **BLOCKED** |

## Example Output

```
🔍 MAGIKA + BRAVE LV3 + OPENCLAW EXEC 聯動
══════════════════════════════════════════════════
📌 Command: python download.py

[Step 1] Extract file paths...
   Found: download.py

[Step 2] Magika AI scan...
   🌀 download.py
      → python | text/x-python (ALLOW) | Score: 0.9992

[Step 3] Risk classification...
   🟢 download.py: python | text/x-python

   🎯 Risk Level: LOW

[Step 4] Security research...
   (skipped - LOW risk)

[Step 5] Execution decision...
   ✅ LOW RISK: Proceeding with exec...

[Step 6] Executing command...
...
```

## Integration with OpenClaw

This tool is designed to be called before OpenClaw's built-in `exec` command. To fully integrate:

1. **Option A: Wrapper Script** (Recommended)
   - Replace `/exec` calls with `magika_brave_exec.cjs`
   - Provides transparent pre-execution scanning

2. **Option B: Hook Integration**
   - Currently exploring OpenClaw's `before_tool_call` hook API
   - Full integration pending SDK support

## API Keys

Get your API keys from:
- **Brave Search**: https://api.search.brave.com/
- **Felo AI**: https://felo.ai/

## License

MIT License - See LICENSE file

## References

- [Magika by Google](https://github.com/google/magika) - AI-powered file type detection
- [Brave Search API](https://api.search.brave.com/) - Private web search
- [Felo AI](https://felo.ai/) - AI research assistant
- [OpenClaw](https://openclaw.ai/) - Self-hosted AI agent
