# monitor-service/ — Track A / C

User-mode listener. Receives events from the kernel driver in production,
or from simulator/'s watcher during dev/testing on any OS. Normalizes
everything to ../docs/event-schema.json and forwards to feature-extraction/.
