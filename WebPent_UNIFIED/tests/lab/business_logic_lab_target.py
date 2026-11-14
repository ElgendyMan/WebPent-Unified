# tests/lab/business_logic_lab_target.py
"""TC-3 §2 V-2/V-3 — the business-logic + race lab lane.

A small FastAPI application with a REAL checkout state machine and three
surfaces (the dispatch's examples), each with an honest patched variant:

  * PRICE MANIPULATION — POST /api/cart/items trusts a client-supplied
    ``price`` field (vulnerable) vs the server-side price table (patched).
  * COUPON STACKING — POST /api/cart/{id}/coupon re-applies the same code
    (each application halves the total again; vulnerable) vs single-use
    per cart (patched).
  * SINGLE-USE REDEMPTION (the RACY surface, V-3) — POST /api/redeem with
    a check-then-act TOCTOU window (85 ms between the use-check and the
    use-mark; vulnerable) vs an atomic lock around the same window
    (patched — the same window, closed by locking, proving the lock and
    not the window's absence is the fix).

  State machine (observed by the V-2 inferrer):
    CART --(coupon)--> COUPON_APPLIED --(checkout)--> PAID
"""
from __future__ import annotations

import threading
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

PRICE_TABLE: dict[str, float] = {"WIDGET": 100.0, "GADGET": 50.0}
COUPON_MULTIPLIER = 0.5          # each application halves the total
REDEEM_WINDOW_SECONDS = 0.085    # the TOCTOU window (vulnerable variant)

CARTS: dict[str, dict[str, Any]] = {}
_cart_seq = {"n": 0}
_cart_lock = threading.Lock()

_redeem_used: set[str] = set()
_redeem_lock = threading.Lock()   # the patched variant's atomicity


class CartItemRequest(BaseModel):
    sku: str
    price: float | None = None


class CouponRequest(BaseModel):
    code: str


class RedeemRequest(BaseModel):
    code: str


def _new_cart_id() -> str:
    with _cart_lock:
        _cart_seq["n"] += 1
        return f"CART-{_cart_seq['n']:04d}"


def build_app(vulnerable: bool = False) -> FastAPI:
    app = FastAPI(
        title=f"WebPent Business Logic + Race Lab Target (vulnerable={vulnerable})",
        version="0.1.0")

    @app.post("/api/cart/items")
    def add_item(req: CartItemRequest) -> dict[str, Any]:
        if req.sku not in PRICE_TABLE:
            raise HTTPException(status_code=400, detail="unknown sku")
        if vulnerable and req.price is not None:
            # V-2 surface: the client-supplied price is trusted.
            total = float(req.price)
        else:
            total = PRICE_TABLE[req.sku]
        cart_id = _new_cart_id()
        CARTS[cart_id] = {"total": total, "state": "CART", "coupons": []}
        return {"cart_id": cart_id, "total": total, "state": "CART"}

    @app.post("/api/cart/{cart_id}/coupon")
    def apply_coupon(cart_id: str, req: CouponRequest) -> dict[str, Any]:
        cart = CARTS.get(cart_id)
        if cart is None:
            raise HTTPException(status_code=404, detail="cart not found")
        if req.code != "SAVE50":
            raise HTTPException(status_code=400, detail="invalid coupon code")
        if not vulnerable and cart["coupons"]:
            # patched: single-use per cart
            raise HTTPException(status_code=409,
                                detail="coupon already applied to this cart")
        cart["coupons"].append(req.code)
        cart["total"] = round(cart["total"] * COUPON_MULTIPLIER, 2)
        cart["state"] = "COUPON_APPLIED"
        return {"cart_id": cart_id, "total": cart["total"],
                "state": cart["state"], "applied": len(cart["coupons"])}

    @app.post("/api/cart/{cart_id}/checkout")
    def checkout(cart_id: str) -> dict[str, Any]:
        cart = CARTS.get(cart_id)
        if cart is None:
            raise HTTPException(status_code=404, detail="cart not found")
        cart["state"] = "PAID"
        return {"cart_id": cart_id, "total": cart["total"], "state": "PAID"}

    @app.post("/api/redeem")
    def redeem(req: RedeemRequest) -> dict[str, Any]:
        code = req.code
        if code.startswith("BAD-"):
            # the negative-control surface: always rejected
            raise HTTPException(status_code=409, detail="code invalid")
        if vulnerable:
            # V-3 surface: check-then-act with a REAL TOCTOU window.
            if code in _redeem_used:
                raise HTTPException(status_code=409, detail="code already used")
            time.sleep(REDEEM_WINDOW_SECONDS)
            _redeem_used.add(code)
        else:
            # patched: the SAME window, closed by an atomic lock.
            with _redeem_lock:
                if code in _redeem_used:
                    raise HTTPException(status_code=409,
                                        detail="code already used")
                time.sleep(REDEEM_WINDOW_SECONDS)
                _redeem_used.add(code)
        return {"redeemed": True, "code": code, "balance": 90.0}

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok"}

    return app


def start_business_logic_server(vulnerable: bool = False) -> tuple[Any, str]:
    import uvicorn

    app_instance = build_app(vulnerable=vulnerable)
    config = uvicorn.Config(app_instance, host="127.0.0.1", port=0,
                            log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("business logic lab server failed to start")
    port = server.servers[0].sockets[0].getsockname()[1]
    server._lab_thread = thread  # type: ignore[attr-defined]
    server._vulnerable = vulnerable  # type: ignore[attr-defined]
    return server, f"http://127.0.0.1:{port}"
