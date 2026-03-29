# IP Intelligence Analyst Workspace

A Streamlit-based analyst workspace for investigating IP addresses, reviewing lightweight risk indicators, documenting findings, and saving analyst case history.

## Features

- Single IP investigation
- Batch CSV investigation
- Public/private IP classification
- Lightweight risk scoring and flags
- Analyst tagging (`benign`, `needs_review`, `suspicious`, `malicious`)
- Analyst notes and local case history
- Exportable CSV results
- Streamlit-ready dark theme
- Portfolio/demo friendly structure

## Project Structure

```text
IP-Intel-Analyst-Workspace/
├─ app.py
├─ requirements.txt
├─ README.md
├─ .gitignore
├─ assets/
│  └─ banner.png
├─ data/
│  └─ investigations.csv
├─ ip_intel/
│  ├─ __init__.py
│  ├─ service.py
│  └─ storage.py
└─ .streamlit/
   └─ config.toml
```

## Local Setup

1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file in the repo root:
   ```env
   IPINFO_TOKEN=your_ipinfo_token_here
   MAXMIND_CITY_DB=
   ```
4. Run the app:
   ```bash
   python -m streamlit run app.py
   ```

## Batch CSV Format

Your input CSV must contain a column named `ip`.

Example:

```csv
ip
8.8.8.8
1.1.1.1
208.67.222.222
```

## Deployment to Streamlit Community Cloud

1. Push this repository to GitHub.
2. In Streamlit Community Cloud, create a new app from the repository.
3. Set the main file path to:
   ```text
   app.py
   ```
4. Add your `IPINFO_TOKEN` as a Streamlit secret or environment variable before deployment.

## Portfolio Blurb

**IP Intelligence Analyst Workspace** is a Streamlit-based cybersecurity investigation demo that supports single-IP and batch-IP analysis, analyst tagging, notes, saved case history, CSV export, and geolocation review. It is designed as a lightweight analyst-facing workspace for triage and documentation.

## Notes

- `data/investigations.csv` is intended for local demo data only.
- Do not commit real sensitive investigation data.
- The risk score is heuristic and should be treated as triage support, not final attribution.
