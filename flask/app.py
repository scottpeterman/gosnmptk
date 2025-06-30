from flask import Flask, render_template, jsonify, send_file, request, redirect, url_for
import json
import os
import csv
import io
from datetime import datetime
from collections import Counter, defaultdict
import glob

app = Flask(__name__)


class ScannerDataAnalyzer:
    def __init__(self, json_file_path):
        self.json_file_path = json_file_path
        self.data = None
        self.load_data()

    def load_data(self):
        """Load and parse the scanner JSON data"""
        try:
            with open(self.json_file_path, 'r') as f:
                self.data = json.load(f)
        except Exception as e:
            print(f"Error loading {self.json_file_path}: {e}")
            self.data = None

    def get_statistics(self):
        """Extract comprehensive statistics from the scanner data"""
        if not self.data:
            return None

        devices = self.data.get('devices', {})
        stats = self.data.get('statistics', {})

        # Basic counts
        total_devices = len(devices)
        snmp_ready = sum(1 for device in devices.values() if self.is_snmp_ready(device))
        responding = sum(1 for device in devices.values() if self.is_responding(device))

        # Vendor breakdown
        vendor_breakdown = defaultdict(int)
        device_type_breakdown = defaultdict(int)
        confidence_scores = []
        scan_dates = []

        for device in devices.values():
            vendor = device.get('vendor', 'unknown').lower()
            device_type = device.get('device_type', 'unknown').lower()
            confidence = device.get('confidence_score', 0)

            vendor_breakdown[vendor] += 1
            device_type_breakdown[device_type] += 1

            if confidence > 0:
                confidence_scores.append(confidence)

            # Extract scan dates
            if device.get('last_seen'):
                scan_dates.append(device['last_seen'])

        # Calculate averages
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0

        # Subnet analysis
        subnet_breakdown = defaultdict(int)
        for device in devices.values():
            ip = device.get('primary_ip', '')
            if ip:
                # Extract /24 subnet
                ip_parts = ip.split('.')
                if len(ip_parts) >= 3:
                    subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                    subnet_breakdown[subnet] += 1

        return {
            'total_devices': total_devices,
            'snmp_ready': snmp_ready,
            'responding': responding,
            'vendor_breakdown': dict(vendor_breakdown),
            'device_type_breakdown': dict(device_type_breakdown),
            'subnet_breakdown': dict(subnet_breakdown),
            'avg_confidence': round(avg_confidence, 2),
            'scan_dates': scan_dates,
            'last_scan': max(scan_dates) if scan_dates else None,
            'first_scan': min(scan_dates) if scan_dates else None
        }

    def is_snmp_ready(self, device):
        """Check if device has SNMP data"""
        return bool(device.get('snmp_data_by_ip', {}) or
                    device.get('sys_descr') or
                    device.get('sys_name'))

    def is_responding(self, device):
        """Check if device is responding (has been seen)"""
        return device.get('last_seen') is not None

    def get_device_details(self):
        """Get detailed device information for export"""
        if not self.data:
            return []

        devices = self.data.get('devices', {})
        device_list = []

        for device_id, device in devices.items():
            device_info = {
                'device_id': device_id,
                'primary_ip': device.get('primary_ip', ''),
                'all_ips': ', '.join(device.get('all_ips', [])),
                'vendor': device.get('vendor', 'unknown'),
                'device_type': device.get('device_type', 'unknown'),
                'sys_descr': device.get('sys_descr', ''),
                'sys_name': device.get('sys_name', ''),
                'first_seen': device.get('first_seen', ''),
                'last_seen': device.get('last_seen', ''),
                'scan_count': device.get('scan_count', 0),
                'confidence_score': device.get('confidence_score', 0),
                'detection_method': device.get('detection_method', ''),
                'snmp_ready': self.is_snmp_ready(device),
                'responding': self.is_responding(device)
            }
            device_list.append(device_info)

        return sorted(device_list, key=lambda x: x['primary_ip'])


def get_available_json_files():
    """Get list of available JSON scanner files"""
    json_files = []
    seen_files = set()  # Track files we've already found to avoid duplicates

    # Look for JSON files in current directory and common scanner locations
    search_patterns = [
        '*.json',
        'scans/*.json',
        'data/*.json'
    ]

    for pattern in search_patterns:
        for file_path in glob.glob(pattern):
            if os.path.isfile(file_path):
                # Use absolute path to avoid duplicates
                abs_path = os.path.abspath(file_path)
                if abs_path in seen_files:
                    continue
                seen_files.add(abs_path)

                try:
                    # Try to load and validate it's a scanner file
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if 'devices' in data or 'statistics' in data:
                            stat = os.stat(file_path)
                            json_files.append({
                                'filename': os.path.basename(file_path),
                                'path': file_path,
                                'size': stat.st_size,
                                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                                'device_count': len(data.get('devices', {}))
                            })
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
                    continue

    return sorted(json_files, key=lambda x: x['modified'], reverse=True)


@app.route('/')
def index():
    """Main page showing available scanner files"""
    json_files = get_available_json_files()
    return render_template('index.html', json_files=json_files)


@app.route('/report/<path:filename>')
def report(filename):
    """Generate report for specific JSON file"""
    if not os.path.exists(filename):
        return "File not found", 404

    analyzer = ScannerDataAnalyzer(filename)
    stats = analyzer.get_statistics()

    if not stats:
        return "Error loading file data", 500

    return render_template('report.html',
                           filename=os.path.basename(filename),
                           stats=stats)


@app.route('/api/stats/<path:filename>')
def api_stats(filename):
    """API endpoint for statistics data"""
    if not os.path.exists(filename):
        return jsonify({'error': 'File not found'}), 404

    analyzer = ScannerDataAnalyzer(filename)
    stats = analyzer.get_statistics()

    if not stats:
        return jsonify({'error': 'Error loading file data'}), 500

    return jsonify(stats)


@app.route('/export/<path:filename>')
def export_csv(filename):
    """Export device data as CSV"""
    if not os.path.exists(filename):
        return "File not found", 404

    analyzer = ScannerDataAnalyzer(filename)
    devices = analyzer.get_device_details()

    if not devices:
        return "No device data found", 404

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'device_id', 'primary_ip', 'all_ips', 'vendor', 'device_type',
        'sys_descr', 'sys_name', 'first_seen', 'last_seen', 'scan_count',
        'confidence_score', 'detection_method', 'snmp_ready', 'responding'
    ])

    writer.writeheader()
    for device in devices:
        writer.writerow(device)

    # Convert to bytes for file response
    output.seek(0)
    csv_data = output.getvalue().encode('utf-8')
    output.close()

    # Create file-like object
    csv_file = io.BytesIO(csv_data)
    csv_file.seek(0)

    base_filename = os.path.splitext(os.path.basename(filename))[0]
    return send_file(
        csv_file,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'{base_filename}_devices.csv'
    )


if __name__ == '__main__':
    # Add the tojson filter to Jinja2 environment
    app.jinja_env.filters['tojson'] = lambda obj: json.dumps(obj)
    app.run(debug=True, host='0.0.0.0', port=5000)