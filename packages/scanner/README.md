# AirLock Scanner

> Source-to-sink firewall for agentic web browsing.

**airlock-codes** is the Python package for the AirLock scanner. It strips prompt injection, hostile instructions, and hidden content before your AI agent sees it.

## Installation

```bash
pip install airlock-codes
```

## CLI

```bash
airlock https://example.com
airlock https://example.com --json
```

## Library

```python
from airlock import scan

result = scan("https://example.com")
print(result["page_risk"], result["trust_level"])
```

## Documentation

Full documentation at [airlock.codes](https://airlock.codes)