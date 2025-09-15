from fastapi import FastAPI

app = FastAPI()

@app.post("/submit")
async def submit_data(data: dict):
    return {"message": "✅ Request reached backend service", "data": data}


if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Backend Service...")
    uvicorn.run("backend:app", host="127.0.0.1", port=9000, reload=True)
