import uvicorn
from app import app

if __name__ == "__main__":
    """
    Run the FastAPI Shield Example App directly
    
    To run:
        python main.py
    """
    uvicorn.run(app, host="0.0.0.0", port=8000) 