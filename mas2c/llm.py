"""Provider-neutral chat call: POST $OPENAI_BASE_URL/chat/completions, cached on disk."""
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request

DEFAULT_MODEL = "cpa/claude-sonnet-5"


def chat(messages, model=None):
    model = model or os.environ.get("MAS2C_MODEL", DEFAULT_MODEL)
    body = {"model": model, "messages": messages, "temperature": 0}
    raw = json.dumps(body, sort_keys=True).encode()  # cache key excludes transport flags (stream)
    cache_dir = os.environ.get("MAS2C_CACHE", ".mas2c-cache")
    os.makedirs(cache_dir, exist_ok=True)
    cache = os.path.join(cache_dir, hashlib.sha256(raw).hexdigest() + ".json")
    if os.path.exists(cache):
        with open(cache) as f:
            return json.load(f)["content"]
    base = os.environ["OPENAI_BASE_URL"].rstrip("/")
    # stream=True keeps bytes flowing so proxies/CDNs do not time out long generations
    req = urllib.request.Request(
        base + "/chat/completions", data=json.dumps(dict(body, stream=True)).encode(), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "mas2c/0.1",
                 "Authorization": "Bearer " + os.environ.get("OPENAI_API_KEY", "")})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=900) as r:
                content = _read_sse(r)
            break
        except (urllib.error.URLError, KeyError, json.JSONDecodeError, TimeoutError) as e:
            if attempt == 3 or (isinstance(e, urllib.error.HTTPError) and e.code < 500):
                raise
            time.sleep(10 * (attempt + 1))
    with open(cache, "w") as f:
        json.dump({"model": model, "messages": messages, "content": content}, f, indent=1)
    return content


def _read_sse(resp):
    """Concatenate delta.content from an OpenAI-style SSE stream (falls back to a plain JSON body)."""
    parts, first = [], None
    for line in resp:
        line = line.decode("utf-8", "replace").strip()
        if first is None:
            first = line
            if line.startswith("{"):  # server ignored stream=true
                return json.loads(line + resp.read().decode())["choices"][0]["message"]["content"]
        if not line.startswith("data:") or line == "data: [DONE]":
            continue
        for ch in json.loads(line[5:]).get("choices", []):
            parts.append((ch.get("delta") or {}).get("content") or "")
    return "".join(parts)


def parse_json(text):
    """Strip markdown fences and parse the first JSON object."""
    text = re.sub(r"^\s*```[a-z]*\s*|\s*```\s*$", "", text.strip())
    start = text.find("{")
    return json.loads(text[start:] if start >= 0 else text)
