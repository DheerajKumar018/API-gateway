# backend_multi.py
from fastapi import FastAPI, Request
import uvicorn
import sys

app = FastAPI()

@app.post("/submit")
async def submit(data: dict):
    return {"service": "default", "message": "Request reached backend /submit", "data": data}

@app.post("/auth/login")
async def auth_login(body: dict):
    return {"service": "auth", "path": "/auth/login", "body": body}

@app.post("/users")
async def users_create(body: dict):
    return {"service": "users", "path": "/users", "body": body}

@app.get("/users/{user_id}")
async def users_get(user_id: int):
    return {"service": "users", "path": f"/users/{user_id}", "user_id": user_id}

@app.post("/orders")
async def orders_create(body: dict):
    return {"service": "orders", "path": "/orders", "body": body}

@app.get("/orders/{order_id}")
async def orders_get(order_id: int):
    return {"service": "orders", "path": f"/orders/{order_id}", "order_id": order_id}

if __name__ == "__main__":
    port = 9000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    uvicorn.run("backend:app", host="127.0.0.1", port=port, reload=True)
