# SecAPI — Code Examples (paste-ready)

Replace `SECAPI-API-KEY` with each consumer's RapidAPI key, and
`secapi.p.rapidapi.com` with your actual RapidAPI host (shown in your
dashboard after registration — this is also the host you set in
`SECAPI_EXPECTED_RAPIDAPI_HOST`).

---

## cURL — password breach check

```bash
curl --request POST \
  --url https://secapi.p.rapidapi.com/api/v1/password-iq/breach \
  --header 'content-type: application/json' \
  --header 'x-rapidapi-host: secapi.p.rapidapi.com' \
  --header 'x-rapidapi-key: SECAPI-API-KEY' \
  --data '{"password":"password123"}'
```

## cURL — scan a dependency manifest

```bash
curl --request POST \
  --url https://secapi.p.rapidapi.com/api/v1/cve-scan/scan \
  --header 'content-type: multipart/form-data' \
  --header 'x-rapidapi-host: secapi.p.rapidapi.com' \
  --header 'x-rapidapi-key: SECAPI-API-KEY' \
  --form 'file=@requirements.txt'
```

## Python (requests)

```python
import requests

url = "https://secapi.p.rapidapi.com/api/v1/password-iq/breach"
headers = {
    "content-type": "application/json",
    "x-rapidapi-host": "secapi.p.rapidapi.com",
    "x-rapidapi-key": "SECAPI-API-KEY",
}
resp = requests.post(url, json={"password": "password123"}, headers=headers)
print(resp.json())
# {'password_provided': True, 'hash_prefix': 'CBFDA',
#  'confirmed_breached': True, 'times_seen': 2266543}
```

## JavaScript (fetch)

```js
const resp = await fetch(
  "https://secapi.p.rapidapi.com/api/v1/log-correlate/ingest",
  {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-rapidapi-host": "secapi.p.rapidapi.com",
      "x-rapidapi-key": "SECAPI-API-KEY",
    },
    body: JSON.stringify({
      source: "ids",
      payload: { event_type: "privilege", action: "escalate", user: "root" },
    }),
  }
);
console.log(await resp.json());
// { event_id: '...', alert_count: 1, alerts: [ { rule_id: 'R-1003', ... } ] }
```

## Go

```go
body := bytes.NewReader([]byte(`{"package":"requests","version":"2.30.0","ecosystem":"PyPI"}`))
req, _ := http.NewRequest("POST",
    "https://secapi.p.rapidapi.com/api/v1/cve-scan/osv", body)
req.Header.Set("content-type", "application/json")
req.Header.Set("x-rapidapi-host", "secapi.p.rapidapi.com")
req.Header.Set("x-rapidapi-key", "SECAPI-API-KEY")
resp, err := http.DefaultClient.Do(req)
```

---

## Rate limiting & errors

- 4xx = your request is wrong (missing params, bad input, or 403 if the
  RapidAPI host gate is on). Fix the input — you are not billed for these.
- 502 = upstream (HIBP/OSV/AbuseIPDB) temporarily unavailable. Retry later.
- Check the `x-ratelimit-*` response headers for your tier limits.