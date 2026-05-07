# DefMon

DefMon is a SIEM/SOAR platform that ingests access logs, classifies events as normal or malicious, raises alerts, and executes playbook actions (block IP, create incident, notifications).

## Start Stack

```bash
docker compose up --build -d
docker compose exec defmon-api alembic upgrade head
docker compose exec defmon-api python -m defmon.bootstrap --username admin --password admin
```

- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

## Sender-Based Ingestion

DefMon accepts remote logs at:

`POST /api/senders/ingest?sender_id=<id>&sender_key=<key>`

Create a sender with an admin token:

```bash
curl -X POST "http://127.0.0.1:8000/api/senders" \
  -H "Authorization: Bearer <ADMIN_JWT>" \
  -H "Content-Type: application/json" \
  -d '{"name":"terminal-2-sender","description":"Second terminal replay sender"}'
```

Save `sender.id` and `api_key`.

## Second Terminal Simulation (Windows)

Open a second terminal and run:

```powershell
python scripts/windows_log_simulator.py `
  --api-base "http://127.0.0.1:8000" `
  --sender-id "<SENDER_ID>" `
  --sender-key "<SENDER_KEY>" `
  --source-log "data/real_access_source.log" `
  --inject-every 6 `
  --batch-size 20
```

What this does:

- Replays real combined-format access log lines from `data/real_access_source.log`
- Injects malicious payloads into every Nth original URI (not synthetic standalone lines)
- Sends batches to DefMon ingest endpoint from terminal 2

## Validate Detection and Playbooks

Check ingested logs:

```bash
curl -H "Authorization: Bearer <JWT>" \
  "http://127.0.0.1:8000/api/logs/received?limit=100"
```

Check alerts:

```bash
curl -H "Authorization: Bearer <JWT>" \
  "http://127.0.0.1:8000/api/alerts?limit=100"
```

Check incidents:

```bash
curl -H "Authorization: Bearer <JWT>" \
  "http://127.0.0.1:8000/api/incidents?limit=100"
```

Check automated SOAR actions:

```bash
curl -H "Authorization: Bearer <JWT>" \
  "http://127.0.0.1:8000/api/audit?limit=100"
```

Look for `block_ip`, `create_incident`, and `send_alert_notification` entries.
