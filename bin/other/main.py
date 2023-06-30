import sys
import os
from datetime import datetime
from fastapi import FastAPI
import uvicorn
from faker import Faker
from faker.providers import internet, file, person

try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))
    from genedr import Alert, Alerts, Query
except ImportError as e:
    raise Exception(f"Could not import: {str(e)}")

app = FastAPI()


@app.head("/")
async def root():
    pass


@app.post("/api/v1/authenticate/simple")
async def auth():
    return {"secret": "1f10d113-e9e7-4174-b6e1-f8de66da7d1c", "expiry": str(datetime.utcnow())}


@app.api_route("/api/v1/alerts", methods=["QUERY"])
async def alerts(query: Query) -> Alerts:
    fake = Faker()
    fake.add_provider(internet)
    fake.add_provider(file)
    fake.add_provider(person)

    chunked_alerts = Alerts()

    for n in range(query.take):
        alert_id = fake.random_number(digits=16)
        process = f"{fake.file_name()}.exe"
        cmd = f"C:\\Users\\{fake.first_name()[:3]}{fake.last_name()[:3]}\\AppData\\Local\\Programs\\Common" \
              f"\\Windows\\{process}"
        alert = Alert(
            action=fake.random_choices(elements=("allowed", "denied", "unknown")),
            alert_id=alert_id,
            alert_link=f"https://edr.company.com/alerts/{alert_id}",
            src_host=None,
            src_ip=fake.ipv4_public,
            src_port=fake.random_int(min=49152, max=65535),
            dest_host=f"{fake.domain_word()}.company.com",
            dest_ip=fake.ipv4_private(),
            dest_port=3389,
            parent_process="cmd",
            process=process,
            cmdline=f"schtasks /create /rl highest /sc ONLOGON /tn \"Windows Services 19\" /tr \"{cmd}\"",
            signature="",
            url=""
        )
        chunked_alerts.entries += alert

    return chunked_alerts


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, http="h11")
