"""Run Gitleaks Cloud - GitHub API Key Hunter & Secret Scanner on Apify and print each dataset row as JSON.

    pip install apify-client
    APIFY_TOKEN=... python run.py
"""
import json
import os
import pathlib

from apify_client import ApifyClient

client = ApifyClient(os.environ["APIFY_TOKEN"])
run_input = json.loads((pathlib.Path(__file__).parent / "input.json").read_text())
run = client.actor("anshumanatrey/gitleaks-github-secret-scanner").call(run_input=run_input)
for item in client.dataset(run["defaultDatasetId"]).iterate_items():
    print(json.dumps(item, ensure_ascii=False))
