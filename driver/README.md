# driver/ — Track A (Windows only)

WDK mini-filter driver, C/C++. Hooks IRP_MJ_CREATE, IRP_MJ_WRITE, and
IRP_MJ_SET_INFORMATION (covers rename/delete). Streams events to
monitor-service/ via FltCreateCommunicationPort / FltSendMessage,
formatted per ../docs/event-schema.json.
