"""
Customer record helpers — single source of truth for reading customers.json.

Used by routes/admin.py (customer CRUD) and tools/sentinel_client.py (per-customer
Sentinel SP credential lookup). Kept in tools/ so that tools/ never has to import
from routes/.
"""
import json
import os
from typing import Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CUSTOMERS_FILE = os.path.join(BASE_DIR, "data", "customers.json")


def load_customers() -> list:
    """Read all customer records. Returns [] if the file does not exist yet."""
    if not os.path.exists(CUSTOMERS_FILE):
        return []
    with open(CUSTOMERS_FILE) as f:
        return json.load(f)


def save_customers(customers: list) -> None:
    """Persist the full customer list."""
    os.makedirs(os.path.dirname(CUSTOMERS_FILE), exist_ok=True)
    with open(CUSTOMERS_FILE, "w") as f:
        json.dump(customers, f, indent=2)


def get_customer(customer_id: str) -> Optional[dict]:
    """Return the customer record for the given id, or None if not found."""
    if not customer_id:
        return None
    for c in load_customers():
        if c.get("id") == customer_id:
            return c
    return None
