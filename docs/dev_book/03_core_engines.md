# Chapter 3: The Engine Room ⚙️

## 1. The Heuristic Engine: Port-to-Process Correlation
The core of Meteor's intelligence is the ability to link an open network port to a running process on the system.

### Logic:
1.  **ScannerEngine** (Provider-based) finds listening ports.
2.  **ProcessManager** (Provider-based) identifies processes and their PIDs.
3.  **HeuristicEngine** performs the merge. 

> [!TIP]
> **Risk Scoring**: If the `exe_path` of a process on a listening port is inaccessible (Permission Denied), the engine marks it as **Red**. This is a classic indicator of a hidden process or a rootkit using **Process Hollowing**.

## 2. DeepScanner: Integrity Logic
In **Combat Mode** (Root), the `DeepScanner` analyzes process memory mapping.
1.  It reads `/proc/[pid]/maps`.
2.  It looks for the `x` (executable) bit.
3.  If the region is **Anonymous** (not backed by a file on disk), it flags it.
4.  This is a sophisticated detection for **Code Injection**.

## 3. The KillChain Analyzer: Holistic Score
This engine takes inputs from every other system (Hardware, Logs, Heuristics, External Intel) and produces a 0-100 score. 

### Weighting:
- **Hardware Vulnerability**: +15 per vulnerability.
- **Log Anomaly**: +15 per anomaly.
- **Red Process Risk**: +25.
- **Bad External Reputation**: +20.
