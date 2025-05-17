import subprocess
import sys
import os
import signal

def run_process(command, cwd):
    print(f"Running command: {' '.join(command)} in {cwd}")
    return subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
        text=True
    )

if __name__ == "__main__":
    base_dir = os.path.abspath("C:/MyProjects/phising_detection")  # Use your actual base path here
    backend_dir = os.path.join(base_dir, "phising-detection-backend")
    frontend_dir = os.path.join(base_dir, "phising-detection-frontend")

    print("Backend dir exists:", os.path.isdir(backend_dir))
    print("Frontend dir exists:", os.path.isdir(frontend_dir))

    backend_script = "app.py"
    frontend_script = "frontend.py"

    backend_proc = run_process([sys.executable, backend_script], backend_dir)
    print("Backend started...")

    frontend_proc = run_process([sys.executable, "-m", "streamlit", "run", frontend_script], frontend_dir)
    print("Frontend started...")

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("Shutting down processes...")
        backend_proc.send_signal(signal.SIGINT)
        frontend_proc.send_signal(signal.SIGINT)
