# ---------------- app.py ----------------
from flask import Flask, render_template, request, jsonify
import pandas as pd
from werkzeug.utils import secure_filename
import os
import requests

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB max
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Protocol descriptions
PROTOCOL_DESCRIPTIONS = {
    "TCP": "Transmission Control Protocol - Reliable, connection-oriented",
    "UDP": "User Datagram Protocol - Fast, connectionless",
    "HTTP": "HyperText Transfer Protocol - Web traffic",
    "HTTPS": "Secure HTTP",
    "FTP": "File Transfer Protocol",
    "DNS": "Domain Name System",
    "ICMP": "Internet Control Message Protocol",
    "ARP": "Address Resolution Protocol",
    "SMTP": "Simple Mail Transfer Protocol",
    "DHCP": "Dynamic Host Configuration Protocol"
}

# Function to fetch IP info and threat
def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,lat,lon,query")
        data = response.json()
        if data.get('status') == 'success':
            return {
                'ip': data.get('query'),
                'country': data.get('country', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0),
                'threat': evaluate_ip(ip)
            }
    except:
        pass
    return {'ip': ip, 'country':'Unknown','region':'Unknown','city':'Unknown','isp':'Unknown','lat':0,'lon':0,'threat':'Unknown'}

# Fake threat evaluation (demo) – replace with real API if needed
def evaluate_ip(ip):
    harmful_ips = ["192.168.1.50","10.0.0.200"]
    return "⚠ Malicious" if ip in harmful_ips else "✅ Safe"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    if not file.filename.endswith('.csv'):
        return "Invalid file type. Only CSV supported.", 400
    try:
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        df = pd.read_csv(path)
        if 'Source' not in df.columns or 'Protocol' not in df.columns:
            return "CSV must have 'Source' and 'Protocol' columns.", 400

        # Stats
        total_packets = len(df)
        unique_sources_list = df['Source'].unique().tolist()
        unique_protocols_list = df['Protocol'].unique().tolist()
        top_sources = df['Source'].value_counts().head(15)
        top_protocols = df['Protocol'].value_counts().head(15)

        # IP info for top sources
        ip_info_dict = {ip: get_ip_info(ip) for ip in top_sources.index}

        # Protocol info
        protocol_info_dict = {proto: PROTOCOL_DESCRIPTIONS.get(proto.upper(), "Unknown Protocol") for proto in top_protocols.index}

        # Top destinations
        top_destinations = None
        if 'Destination' in df.columns:
            top_destinations = df['Destination'].value_counts().head(15)

        return jsonify({
            'file_info': {'name': filename, 'size_kb': round(os.path.getsize(path)/1024,2), 'rows': df.shape[0], 'columns': df.shape[1]},
            'stats': {
                'total_packets': total_packets,
                'unique_sources_list': unique_sources_list,
                'unique_protocols_list': unique_protocols_list,
                'most_active_device': top_sources.index[0],
                'most_used_protocol': top_protocols.index[0]
            },
            'top_sources': {
                'labels': top_sources.index.tolist(),
                'counts': top_sources.values.tolist(),
                'ip_info': ip_info_dict
            },
            'top_protocols': {
                'labels': top_protocols.index.tolist(),
                'counts': top_protocols.values.tolist(),
                'protocol_info': protocol_info_dict
            },
            'top_destinations': {'labels': top_destinations.index.tolist(), 'counts': top_destinations.values.tolist()} if top_destinations is not None else None,
            'preview': df.head(10).to_dict(orient='records')
        })
    except Exception as e:
        return f"Error processing file: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
