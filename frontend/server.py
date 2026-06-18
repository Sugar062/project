import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="E-Commerce & Security Portal Server", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Locate the frontend directory path
FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))

# Mount the static files directory. 
# FastAPI will serve index.html by default when hitting "/"
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    # Start the server on Port 8000
    uvicorn.run(app, host="127.0.0.1", port=8000)
