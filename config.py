from flask import Flask, render_template, request, redirect, jsonify
import json
import subprocess
import os
import signal

app = Flask(__name__)

# Global variable to store the firewall process
firewall_process = None

# Load firewall rules from JSON file
def load_rules():
    with open('firewallrules.json', 'r') as f:
        return json.load(f)

# Save firewall rules to JSON file
def save_rules(data):
    with open('firewallrules.json', 'w') as f:
        json.dump(data, f, indent=4)

@app.route('/')
def index():
    rules = load_rules()
    return render_template('index.html', 
                           banned_ips=rules['ListOfBannedIpAddr'], 
                           banned_ports=rules['ListOfBannedPorts'], 
                           banned_prefixes=rules['ListOfBannedPrefixes'])

@app.route('/update_banned_ips', methods=['POST'])
def update_banned_ips():
    new_ips = request.form.getlist('banned_ips[]')
    rules = load_rules()
    rules['ListOfBannedIpAddr'] = new_ips
    save_rules(rules)
    return redirect('/')

@app.route('/update_banned_ports', methods=['POST'])
def update_banned_ports():
    new_ports = request.form.getlist('banned_ports[]')
    rules = load_rules()
    rules['ListOfBannedPorts'] = new_ports
    save_rules(rules)
    return redirect('/')

@app.route('/update_banned_prefixes', methods=['POST'])
def update_banned_prefixes():
    new_prefixes = request.form.getlist('banned_prefixes[]')
    rules = load_rules()
    rules['ListOfBannedPrefixes'] = new_prefixes
    save_rules(rules)
    return redirect('/')

@app.route('/remove_rule', methods=['POST'])
def remove_rule():
    data = request.json
    rule_type = data.get('type')
    value = data.get('value')

    rules = load_rules()

    if rule_type == 'ip' and value in rules['ListOfBannedIpAddr']:
        rules['ListOfBannedIpAddr'].remove(value)
    elif rule_type == 'port' and value in rules['ListOfBannedPorts']:
        rules['ListOfBannedPorts'].remove(value)
    elif rule_type == 'prefix' and value in rules['ListOfBannedPrefixes']:
        rules['ListOfBannedPrefixes'].remove(value)

    save_rules(rules)
    return jsonify({'status': 'success'}), 200

@app.route('/start_firewall', methods=['POST'])
def start_firewall():
    global firewall_process
    if firewall_process is None or firewall_process.poll() is not None:
        # Start the firewall script
        firewall_process = subprocess.Popen(['python3', 'Firewall.py'])
        return jsonify({'status': 'success', 'message': 'Firewall started.'})
    else:
        return jsonify({'status': 'error', 'message': 'Firewall is already running.'})

@app.route('/stop_firewall', methods=['POST'])
def stop_firewall():
    global firewall_process
    if firewall_process is not None:
        try:
            # Send SIGINT to simulate CTRL+C
            firewall_process.send_signal(signal.SIGINT)
            firewall_process.wait()  # Wait for the process to terminate
            firewall_process = None
            return jsonify({'status': 'success', 'message': 'Firewall stopped.'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Error stopping firewall: {str(e)}'})
    else:
        return jsonify({'status': 'error', 'message': 'Firewall is not running.'})

if __name__ == "__main__":
    try:
        app.run(debug=True, host="0.0.0.0", port=5000)
    except OSError as e:
        if e.errno == 98:  # Error number 98 means the port is already in use
            print("Port 5000 is already in use. Please stop the existing Flask instance.")
        else:
            raise
