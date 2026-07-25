# Event Schema

Every module that produces or consumes file-system events — the kernel
driver, the dev-machine watcher, the simulator, and feature-extraction —
speaks this same schema (see event-schema.json). That's what lets Track B
build and test the full pipeline on a Mac using stand-in events, then
swap in the real driver's output later without touching downstream code.

## Why each field is there

| Field | Why it's here |
|---|---|
| `event_id` | Unique key per event — useful once you're deduplicating or debugging out-of-order delivery |
| `session_id` | Ties a batch of events back to one simulator run — this is how you compute per-session features and assign `label` |
| `timestamp` | Needed for every rate-based feature (files/sec, sequential-pattern timing) |
| `pid` / `process_name` / `process_path` | You're classifying a *process*, not a single event — features get aggregated per process per session |
| `operation` | CREATE/WRITE/RENAME/DELETE/SET_INFO/READ — overwrite ratio and extension-churn are both derived from the mix of operations a process performs |
| `file_path` | Lets you compute directories-touched and sequential-modification-pattern (many real ransomware strains process directories in sorted order — a human rarely does) |
| `file_extension_before/after` | Direct signal for extension-churn, one of your synopsis's named features |
| `file_size_bytes` | Context for entropy-delta — entropy on a 200-byte file is noisier than on a 200KB one |
| `source` | Keeps dev-machine artifacts (`watchdog_dev`), synthetic runs (`simulator`), and real driver output (`kernel_driver`) distinguishable, so you never accidentally train on the wrong mix |
| `label` | `0`/`1` ground truth, set only for controlled simulator runs where you know what you generated — `null` otherwise |

## Example event

```json
{
  "event_id": "b3f1c2a0-1e4d-4b8a-9c2e-6f0a1d2b3c4d",
  "session_id": "sim-run-0042",
  "timestamp": "2026-07-24T10:15:32.104Z",
  "pid": 8841,
  "process_name": "ransomware_pattern_generator.exe",
  "process_path": "C:\\dev\\simulator\\ransomware_pattern_generator.exe",
  "operation": "WRITE",
  "file_path": "C:\\dev\\test-sandbox\\invoice_2024.docx",
  "file_extension_before": ".docx",
  "file_extension_after": ".docx.locked",
  "file_size_bytes": 48213,
  "source": "simulator",
  "label": 1
}
```
