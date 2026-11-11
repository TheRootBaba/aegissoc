# Demo and screenshot capture

The screenshots in this project should come from the running application, with a real authenticated session and a controlled lab dataset. Do not use generated dashboard mockups as product evidence. Do not capture customer telemetry, access tokens, internal hostnames or credentials.

## Prepare a reviewable demo workspace

1. Start the local Compose stack and confirm the API and PostgreSQL are healthy.
2. Create or use a dedicated local administrator account. Do not use a production account.
3. Ingest only synthetic events and create a small set of lab alerts, cases and connector records.
4. Confirm the dashboard is showing the intended workspace and that no real personal or customer data is present.
5. Use a clean browser window at desktop resolution.

The root README contains a PowerShell example for ingesting a synthetic event. The dashboard's sections are populated from the API; screenshots should not be edited to add counts, alerts or status labels that the application did not render.

## Install the optional capture dependency

Playwright is only needed to capture screenshots. It is not an application runtime dependency.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install playwright
python -m playwright install chromium
```

## Capture the live dashboard

From the repository root:

```powershell
python scripts/capture_demo.py
```

The script opens Chromium and the local dashboard. Sign in manually with the lab account, wait for the workspace to finish loading, then return to the terminal and press Enter. It saves full-page screenshots for the selected sections under `docs/assets/screenshots`.

To capture a smaller set:

```powershell
python scripts/capture_demo.py --sections overview alerts events cases
```

To capture from a different local or staging deployment:

```powershell
python scripts/capture_demo.py --base-url https://your-staging-host.example --sections overview sources alerts
```

The browser is interactive by design: credentials are entered directly into the application and are not passed as command-line arguments or written to a file by the capture script.

## Review before committing

Inspect each PNG at full size. Remove or blur any real usernames, email addresses, internal IPs, hostnames, case details, tokens, connector URLs or other sensitive information. Prefer a dedicated synthetic workspace over post-processing. Keep the original unedited capture available during review.

Suggested README image set:

| File | What it should show |
|---|---|
| `overview.png` | Workspace overview with populated, synthetic metrics |
| `sources.png` | Source inventory and ingestion health |
| `alerts.png` | Alert queue with evidence-backed lab alerts |
| `events.png` | Normalized event search and event detail |
| `cases.png` | Incident case workflow and linked alerts |
| `connectors.png` | Connector registry and execution state |
| `audit.png` | Audit history and verification status |

Commit only screenshots captured from the application revision being documented. If a section is empty in the lab, either seed it with a documented synthetic scenario or leave that screenshot out. An empty screen should not be presented as a functioning feature demonstration.

## Demo walkthrough

A short reviewer walkthrough can follow this sequence:

1. Open the workspace overview and check service readiness.
2. Inspect source freshness and ingestion outcomes.
3. Search the synthetic event stream for a failed authentication event.
4. Open the related alert and follow its evidence event IDs.
5. Create or inspect a case and review its audit history.
6. Inspect a connector's last execution and cursor state.
7. Review the Sigma rule state and scheduled execution history.
8. Finish with the audit verification result and response approval workflow.

Only demonstrate response delivery against a local test receiver that records the idempotency key. Do not trigger real blocking, account disabling or endpoint isolation during a portfolio demo.
