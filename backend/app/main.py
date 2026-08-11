from fastapi import FastAPI

app = FastAPI(
    title="Web Security Assessor API",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "message": "Web Security Assessor API"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
