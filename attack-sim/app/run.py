import subprocess
import sys

if __name__ == "__main__":
    import uvicorn
    import multiprocessing

    def run_victim():
        import uvicorn
        from victim_api import victim_app
        uvicorn.run(victim_app, host="0.0.0.0", port=8005)

    def run_attacker():
        import uvicorn
        from main import app
        uvicorn.run(app, host="0.0.0.0", port=8003)

    p1 = multiprocessing.Process(target=run_victim)
    p2 = multiprocessing.Process(target=run_attacker)
    p1.start()
    p2.start()
    p1.join()
    p2.join()