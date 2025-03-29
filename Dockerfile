FROM python:3.9-windowsservercore

WORKDIR /app

COPY requirements.txt .
COPY analyze_windows_events.py .

RUN pip install -r requirements.txt
RUN pyinstaller --onefile --name "Windows事件日志分析" analyze_windows_events.py 