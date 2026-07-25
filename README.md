# AI-Assisted Cloud-Aware Ransomware Detection System

Batch B31 · Dept. of ISE, SIT Tumakuru · Guide: Dr. Ramu S

## Current build split
- **Track A** (`driver/`, Windows side of `monitor-service/`) — teammate on Windows
- **Tracks B, C, D** (`simulator/`, `feature-extraction/`, `ml-model/`,
  `backend/`, `cloud-protection/`, `recovery/`, `dashboard/`) — teammate on macOS

## Working across Mac + Windows
Everything in B, C, and D is portable Python/JS and runs fine on macOS
for development. Two things need a real Windows environment eventually:

1. The kernel driver itself (`driver/`) — obviously.
2. Before final model training, run `simulator/`'s two generator scripts
   on Windows at least once too (your teammate's PC, or a free VM via
   UTM / VMware Fusion). `psutil` reports some process metrics
   differently across OSes, and since the finished system only ever
   deploys on Windows, having some Windows-native rows in the training
   data is cheap insurance against train/production mismatch.

See `docs/event-schema.json` for the shared contract every module speaks.
