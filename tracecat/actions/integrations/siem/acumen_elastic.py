"""Elastic Security integration.

Authentication method: Token-based (with username and password to generate the token in the UI)

Required resource: secret named `elastic` with the following keys:
- `ELASTIC_API_KEY`: Elastic Security API key
- `ELASTIC_API_URL`: Elastic Security API URL

Supported APIs:

```python
list_alerts = {
    "endpoint": "<kibana host>:<port>/api/detection_engine/signals/search",
    "method": "POST",
    "ocsf_schema": "array[detection_finding]",
    "reference": "https://www.elastic.co/guide/en/security/current/signals-api-overview.html#_get_alerts,
}
```
"""

import os
from datetime import datetime
from typing import Annotated, Any

import httpx

from tracecat.registry import Field, RegistrySecret, registry

acumen_elastic_secret = RegistrySecret(
    name="acumen-elastic",
    keys=["ACUMEN_ELASTIC_API_KEY", "ACUMEN_ELASTIC_API_URL"],
)
"""Elastic secret.

Secret
------
- name: `acumen-elastic`
- keys:
    - `ACUMEN_ELASTIC_API_KEY`
    - `ACUMEN_ELASTIC_API_URL`

Example Usage
-------------
Environment variable:
>>> os.environ["ACUMEN_ELASTIC_API_KEY"]

Expression:
>>> ${{ SECRETS.acumen-elastic.ACUMEN_ELASTIC_API_KEY }}
"""


@registry.register(
    default_title="CHANGED - Acumen - List Elastic Security alerts",
    description="Fetch all alerts from Elastic Security and filter by time range.",
    display_group="Acumen - Elastic",
    namespace="integrations.elastic",
    secrets=[acumen_elastic_secret],
)
async def acumen_list_elastic_alerts(
    start_time: Annotated[
        datetime,
        Field(..., description="Start time, return alerts created after this time."),
    ],
    end_time: Annotated[
        datetime,
        Field(..., description="End time, return alerts created before this time."),
    ],
    limit: Annotated[
        int, Field(default=100, description="Maximum number of alerts to return.")
    ] = 100,
) -> list[dict[str, Any]]:
    api_key = os.getenv("ACUMEN_ELASTIC_API_KEY")
    api_url = os.getenv("ACUMEN_ELASTIC_API_URL")

    url = f"{api_url}/api/detection_engine/signals/search"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {api_key}",
        "kbn-xsrf": "kibana",
    }
    query = {
    "size": limit,
    "query": {
        "bool": {
            "filter": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat(),
                        }
                    }
                },
                {"match": {"signal.status": "open"}}
            ],
            "must_not": [
                {
                    "exists": {
                        "field": "kibana.alert.building_block_type"
                    }
                }
            ]

        }
    }
}

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(url, headers=headers, json=query)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json()
