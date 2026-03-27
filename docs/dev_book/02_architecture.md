# Chapter 2: High-Level Architecture 🏗️

## The Clean Architecture
Meteor is built to survive OS migrations. We achieve this by strictly separating **Interface** from **Implementation**.

### 1. The Provider Layer (The OS Bridge)
We don't call `psutil` or `scapy` directly in the CLI. We wrap them in **Providers**.
- **`BaseProvider`**: Defines the "Contract".
- **`UbuntuProvider`**: Implements the contract for Linux.
- **Future**: `WindowsProvider`, `MacOSProvider`, and eventually `SDRProvider` for **Mesh-War**.

### 2. The Engine Layer (The Brains)
Engines are pure logic. They take data from Providers and output "Intelligence". 
- **Example**: `HeuristicEngine` doesn't know *how* ports are found; it only knows how to compare them to process lists.

### 3. The Representation Layer (The Nebula HUD)
The CLI uses `rich` to render the Nebula Dashboard. This layer is entirely swappable (e.g., for a Web UI or JSON API) without touching a single line of logic in the Engines.

```mermaid
graph LR
    User -->|CLI/HUD| Presentation
    Presentation -->|Commands| Engines
    Engines -->|Data Requests| Providers
    Providers -->|Syscalls/APIs| OS_Hardware
```
