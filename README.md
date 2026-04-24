# Machine Learning Based Intrusion Detection System (IDS)

This project implements the **Machine Learning based Intrusion Detection System** described in the provided report:
- Data preprocessing (cleaning, encoding, scaling)
- XGBoost model training and evaluation
- Intrusion detection on uploaded datasets
- Visualization dashboard with email + password login
- PDF report generation + optional email delivery (SMTP)
- Optional live monitoring (packet sniffing) with a safe fallback simulation

## Quickstart

### 1) Setup

```bash
cd /home/dell/project-endsem
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) One-command demo setup (NSL-KDD)

This will download NSL-KDD CSVs, create `data/train.csv` + `data/test.csv` with a `label` column, and train the model.

```bash
python scripts/setup_demo.py
```

### 3) Train a model (using your dataset CSV)

Put a CSV dataset at `data/train.csv` (or provide a path). The CSV must include a label column:
- default label column name: `label`
- label values: `normal` / `attack` (case-insensitive), or `0/1`

```bash
python -m ids.train --data data/train.csv --label-col label --out models/ids_model.joblib
```

### 4) Run the dashboard

```bash
streamlit run app/streamlit_app.py
```

### Login / Sign up

- **Sign up**: create an account with email + password (stored locally in `data/app_users.json` with hashed passwords).
- **Login**: use the same email/password.

Optional fixed “single user” login via env / Streamlit secrets (useful on Streamlit Cloud if you don’t want local user storage):

- `IDS_USER`: email
- `IDS_PASS`: password

```bash
IDS_USER=you@example.com IDS_PASS=yourpass streamlit run app/streamlit_app.py
```

### 5) PDF report (dashboard)

On **Home**, use **Generate PDF report** and **Download last generated PDF**.  
Run **Upload & Scan → Run Detection** first if you want scan summary in the PDF.

### 6) Synthetic test datasets (KB / MB / ~2 GB)

For load testing, generate NSL‑KDD‑shaped CSVs:

```bash
python scripts/generate_test_datasets.py --skip-2gb
```

Full run (writes ~2 GB — needs free disk and time):

```bash
python scripts/generate_test_datasets.py
```

Outputs under `data/synth/` by default: `synth_small_kb.csv` (~tens of KB), `synth_medium_mb.csv` (~30 MB), `synth_large_2gb.csv` (~2 GB). Tune with `--kb-rows`, `--mb-target`, `--target-gb`.

## Data notes (NSL-KDD / CICIDS2017)

The report references NSL-KDD and CICIDS2017. Those datasets are large and not bundled here.
You can export them to CSV and point `ids.train` to the CSV.

## Project structure

- `ids/`: core package (preprocess, model, predict, live monitoring helpers)
- `app/`: Streamlit dashboard (auth, upload, charts, live view)
- `models/`: saved model artifacts (created after training)
- `data/`: your datasets (not committed by default)
- `Dockerfile` / `render.yaml`: deploy to [Render](https://render.com)

## Deploy: GitHub (`santoshi-33` or any account) + Render

### 1) Push this repo to GitHub (example: `santoshi-33/ids`)

Create an empty repository on GitHub (no README) under the account you want, e.g. `https://github.com/santoshi-33/ids`, then from your machine:

```bash
cd /path/to/project-endsem
git remote add santoshi git@github.com:santoshi-33/ids.git
git push -u santoshi main
```

(Use HTTPS + token if you do not use SSH.) If the repo already has `origin` to another user, you can keep both remotes or set `santoshi` as the only `origin` after re-adding it.

### 2) Deploy on Render

1. [Render](https://dashboard.render.com) → **New** → **Blueprint** (or **Web Service**).
2. Connect the GitHub repo (e.g. `santoshi-33/ids`).
3. If you use **Blueprint**, select `render.yaml` — it builds with **Docker** using `./Dockerfile`.
4. In **Environment**, set at least:
   - `IDS_USER` = your demo login email  
   - `IDS_PASS` = your demo password  

(Without a model in the image, the app offers **“Setup demo (download + train)”** in the UI; first run can take several minutes. For more RAM, upgrade the Render instance.)

### 3) Local Docker (optional)

```bash
docker build -t ml-ids .
docker run -p 8501:8501 -e PORT=8501 -e IDS_USER=you@mail.com -e IDS_PASS=secret ml-ids
```

Open `http://localhost:8501`.

## Commands

- Train: `python -m ids.train --data data/train.csv --label-col label`
- Predict CSV: `python -m ids.predict --model models/ids_model.joblib --data data/test.csv`

