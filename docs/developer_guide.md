# Meteor: Developer Guide Entry Point 🛰️⚡

Welcome to the development ecosystem of **Spark Systems** (برق للأنظمة). 

Meteor is built with a focus on **Clean Architecture**, **Stealth**, and **Extensibility**. This document serves as a high-level overview. For deep technical details, architectural blueprints, and the strategic roadmap (including **Mesh-War**), please refer to our full handbook.

## 📖 [The Spark Systems: Cyber Intel Handbook](dev_book/index.md)

### Quick Reference
- **Core Engine**: `meteor/core/`
- **OS Abstraction**: `meteor/providers/`
- **External Spying**: `meteor/external/`
- **Security Vault**: `meteor/core/vault.py`

### Development Rules
1.  **Always use Providers** for any OS-level calls (e.g., `psutil`, `scapy`).
2.  **Maintain K-Anonymity** for all identity/breach checks.
3.  **Modular Everything**: Engines must be testable without the CLI.

---
*For the strategic vision of Spark Systems and the upcoming Mesh-War project, see [Chapter 1](dev_book/01_mission.md) and [Chapter 6](dev_book/06_wireless_intel_future.md) of the handbook.*
