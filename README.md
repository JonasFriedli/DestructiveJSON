# DestructiveJSON
![DestructiveJSON](destructivejson.png)

## Overview

`destructive_json.py` is a single CLI tool that generates various malformed or malicious JSON payloads commonly used in pentesting:

* Deeply nested JSON (stack/recursion tests)
* JSON with many keys (memory/DoS tests)
* JSON with extremely long keys (log/db/processing tests)
* JSON with `__dict__`, `__class__`, `__init__` and other magic keys (attribute injection)
* Malformed JSON (parse-error and info-disclosure tests)
* JSON with `NaN` / `Infinity` tokens (non-standard JSON)
* Duplicate keys (constructed as raw JSON text)
* Mixed payloads combining several techniques

## Requirements

* Python 3.8+

## Usage

### Generate a deeply nested JSON (depth 500):

```bash
python3 destructive_json.py nested -d 500 -o deep.json
```

### Generate many keys (50k keys):

```bash
python3 destructive_json.py manykeys -n 50000 -o many.json
```

### Generate an extremely long key (10k characters):

```bash
python3 destructive_json.py longkey -l 10000 -o long.json
```

### Generate a dunder injection payload:

```bash
python3 destructive_json.py dunder -t all -o dunder.json
```

### Generate malformed JSON:

```bash
python3 destructive_json.py malformed -m unclosed -o broken.json
```

### Generate NaN/Infinity tokens (text output):

```bash
python3 destructive_json.py naninf -o naninf.json
```

### Generate a mixed set of payloads into a directory:

```bash
python3 destructive_json.py all --outdir payloads --depth 200 --many 20000 --long 2000
```

## Example: send generated payloads with curl

```bash
curl -i -X POST http://127.0.0.1/myREST \
  -H 'Content-Type: application/json' \
  --data-binary @deep.json
```
