"""
Export OSV data to GCS.

Individual JSON files are exported to the following path:
    gs://<BUCKET>/<ADVISORY_ID>.json
"""
import argparse
import requests
import json
from datetime import datetime, timedelta

from google.cloud import storage


def main(args):
    # Connect to GCS
    client = storage.Client()
    bucket = client.get_bucket(args.bucket)

    time_after = None
    if args.nightly:
        time_after = (datetime.now() - timedelta(hours=26)).isoformat("T")

    page = 1
    while True:
        r = requests.get(
            "https://apollo.build.resf.org/api/v3/osv",
            params={
                "page": page,
                "limit": 100,
                "after": time_after,
            },
            timeout=60,
        )
        r.raise_for_status()
        advisories = r.json()["advisories"]
        if not advisories:
            break

        for advisory in advisories:
            advisory_json = json.dumps(advisory)

            file_name = f"{advisory['id']}.json"

            # Skip if file already exists
            blob = bucket.blob(file_name)
            if blob.exists():
                print(f"Skipping {file_name} (already exists)")
                continue

            # Upload to GCS
            blob = bucket.blob(file_name)
            blob.upload_from_string(advisory_json)
            print(f"Uploaded {file_name}")

        page += 1

    print("Done!")


if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bucket",
        help="GCS bucket to export to",
        required=True,
    )
    # Flag for nightly job
    parser.add_argument(
        "--nightly",
        help="Run as nightly job",
        action="store_true",
    )

    # Send args to main
    main(parser.parse_args())
