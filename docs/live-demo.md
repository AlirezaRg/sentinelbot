# Live demo

Length: 5 to 10 minutes. Every command is safe to run on a local machine. The demo generates synthetic events and never attacks a real system or a real host.

## Option A: the offline lab (recommended, no Docker needed)

This shows the rules, scoring and correlation on a laptop. It needs Python 3.12 and the lab venv.

### Preparation (before the demo)

```powershell
py -3.12 -m venv .lab\venv
.lab\venv\Scripts\python.exe -m pip install -e .\agent -e .\detection
.lab\venv\Scripts\python.exe scripts\lab\run_scenario.py all --out .lab\runs
```

Run this once so the outputs exist, and keep the terminal open.

### Step 1: show a healthy system

Show the normal scenario. Three successful logins produce no detections.

```powershell
.lab\venv\Scripts\python.exe scripts\lab\run_scenario.py normal --out .lab\runs
```

Expected: `"events": 3`, `"detections": []`, `"incidents": []`.

### Step 2: show the raw input

```powershell
Get-Content .lab\runs\bruteforce\auth.log
```

Explain: these are the same kind of lines a real `auth.log` contains, with addresses from the documentation range `198.51.100.0/24`.

### Step 3: generate a brute-force attack (synthetic)

```powershell
.lab\venv\Scripts\python.exe scripts\lab\run_scenario.py bruteforce --out .lab\runs
```

Expected: 8 events, 1 detection (`ssh_bruteforce`), 1 incident with risk score 40.

Explain: the eighth failure is the one that crosses the threshold of 5. The first five would have triggered it; the cooldown stops more detections.

### Step 4: show the detection and its score

```powershell
Get-Content .lab\runs\bruteforce\detections.jsonl
```

Point out `risk_score`, `risk_factors` and `severity` in the metadata.

### Step 5: show a correlated incident

```powershell
.lab\venv\Scripts\python.exe scripts\lab\run_scenario.py campaign --out .lab\runs
```

Expected: 2 detections (`ssh_bruteforce` and `root_login`), 1 incident, risk score 60, with the rules listed.

Explain: the root login is from the same source address, three minutes after the brute force. Correlation puts both into one incident. Factors: 35 + 10 + 15 = 60.

### Step 6: show the incident

```powershell
Get-Content .lab\runs\campaign\incidents.json
```

Point out the title, the rules, the event count and the recommended actions.

### Step 7: show the AI fallback

The offline analyst is used when no model is configured. It is tested in `ai/tests/`. This step is a talking point, not a live call, because the live model needs an API key.

Explain: the explanation comes from fixed rule-based text, and `provider` is `rules`.

### Step 8: explain the result

Use the results table in `docs/laboratory-experiments.md` and the limitations in `docs/evaluation.md`. State that six synthetic scenarios passed, that this is not a measurement of accuracy, and that the performance numbers are not yet measured.

## Option B: the full stack (Docker Compose, local host)

Use this only if Docker is installed and the stack has been set up as in `docs/deployment.md`.

1. Show that the services are running:

   ```bash
   docker compose ps
   ```

2. Check the API:

   ```bash
   curl -s http://127.0.0.1:8000/health
   ```

3. Open the dashboard at http://127.0.0.1:3001 and sign in with the demo user.
4. Show the incident list and an incident's detail page.
5. Show Prometheus metrics (requires a viewer token or API key):

   ```bash
   curl -s -H "X-API-Key: $SENTINEL_API_KEY" http://127.0.0.1:8000/metrics | head -40
   ```

   Run this with the key in an environment variable. Do not type the key into the terminal in front of the audience.

6. Open Grafana at http://127.0.0.1:3000 and show the provisioned dashboard.

Do not generate attack traffic against the Compose stack during the demo unless the synthetic events are sent through the lab scripts. The stack's agent reads the host's real authentication logs.

## Things not to do during the demo

- Do not attack any host, including the demo machine, from outside the lab.
- Do not type passwords or API keys in front of the audience.
- Do not show `.env` or `k8s/secret.yaml`.
- Do not claim accuracy or performance numbers that are marked "not yet measured".

## If something fails

- If the lab command fails, check that `.lab\venv` exists and that the packages were installed. The output of the failing command is printed in full.
- If the dashboard shows an error, check `docker compose ps` and `docker compose logs sentinel-api --tail 50`.
- Have the recorded outputs in `.lab\runs` ready as a fallback.
