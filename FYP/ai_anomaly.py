import psutil
import time
from sklearn.ensemble import IsolationForest

THRESHOLD_KB = 1000
COOLDOWN = 8

def collect_data(samples=10): 
    data = []
    prev = psutil.net_io_counters()
    for _ in range(samples):
        time.sleep(1)
        curr = psutil.net_io_counters()
        sent = (curr.bytes_sent - prev.bytes_sent) / 1024
        recv = (curr.bytes_recv - prev.bytes_recv) / 1024
        data.append([max(0, sent), max(0, recv)])
        prev = curr
    return data

def train_model(data):
    if not data: data = [[0, 0]]
    model = IsolationForest(contamination=0.03, random_state=42)
    model.fit(data)
    return model

def detect(model, prev, curr, last_alert_time):
    sent = (curr.bytes_sent - prev.bytes_sent) / 1024
    recv = (curr.bytes_recv - prev.bytes_recv) / 1024
    
    if time.time() - last_alert_time > COOLDOWN:
        if sent > THRESHOLD_KB or recv > THRESHOLD_KB:
            try:
                if model.predict([[sent, recv]])[0] == -1:
                    return True, time.time(), sent, recv
            except: 
                pass
    return False, last_alert_time, sent, recv