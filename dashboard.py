# dashboard.py - Simple Web Dashboard
from flask import Flask, render_template, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

class DashboardData:
    def __init__(self):
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'ips_blocked': 0,
            'system_uptime': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        self.recent_alerts = []
        
    def update_stats(self, new_stats):
        self.stats.update(new_stats)
        
    def add_alert(self, alert):
        self.recent_alerts.insert(0, {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': alert
        })
        # Keep only last 50 alerts
        self.recent_alerts = self.recent_alerts[:50]

dashboard_data = DashboardData()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(dashboard_data.stats)

@app.route('/api/alerts')
def get_alerts():
    return jsonify(dashboard_data.recent_alerts)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
