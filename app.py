import re
import os
import json
import time
import threading
from sh import tail
from flask import Flask
from flask import request
from collections import defaultdict
from subprocess import check_output

def get_ssh_connections():
    PTS_PATTERN = re.compile(r'.*(?P<term>pts/[0-9]+)')
    # Get 'pts' from who command
    connections = {}
    time.sleep(1)
    who_output = check_output(["who", "-p", "-u"]).decode("utf-8")
    who_output = who_output.strip()
    who_output = who_output.replace('+','')
    who_output = who_output.split('\n')
    for who_record in who_output:
        who_record = ' '.join(who_record.split())
        who_record = who_record.split(' ')
        if PTS_PATTERN.match(who_record[1]):
            connections[who_record[5]] = who_record[1]
    print(connections)
    return connections

def collect_running_process_ids():
    # Runs forever in background thread
    PATTERN = re.compile(r'(?P<ts>[A-z]{3,3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (?P<hostname>[^\s]*) (?P<process>[^\[]*)\[(?P<pid>[0-9]+)\]:(?P<msg>.*)')
    PUB_KEY_PATTERN = re.compile(r'(.*)RSA-CERT (?P<fg>.*) .*')
    cache = defaultdict(dict)
    for line in tail("-f", "/var/log/auth.log", _iter=True):
        m = PATTERN.match(line)
        if m:
            process = m.group("process")
            if process == 'sshd':
                pid = m.group("pid")
                msg = m.group("msg")
                if 'userauth_pubkey' in msg:
                    m = PUB_KEY_PATTERN.match(msg)
                    if m:
                        public_key_fg = m.group('fg')
                        connections = get_ssh_connections()
                        if cache[public_key_fg]:
                            pid_array = cache[public_key_fg]["pid"]
                            pid_array.append(pid)
                            if str(pid) in connections.keys():
                                pts_array = cache[public_key_fg]["pts"]
                                if not connections[str(pid)] in pts_array: 
                                    pts_array.append(connections[str(pid)])
                        else:
                            cache[public_key_fg].update({"pid": [pid]})
                            cache[public_key_fg].update({"pts": [connections[str(pid)]]})
        if cache:
            print(json.dumps(cache))
            connection_data = json.dumps(cache)
            f = open('updated_connection_data.json', 'w')
            print >> f, connection_data
            f.close()

log_parser = threading.Thread(target=collect_running_process_ids, name='Thread-Log-Parser')
log_parser.start()
app = Flask(__name__)

# curl -X GET -d "finger_print=SHA256:jV35o0TeaubEPAWGHeS3ElSsUjOlSs/qsB26K/Eq9yA" http://127.0.0.1:5000/kill_active_connections
@app.route('/kill_active_connection', methods=['GET'])
def kill_active_connection():
    finger_print = request.form['finger_print']
    current_connections = []
    with open('updated_connection_data.txt') as json_file:
      current_connections = json.load(json_file)
    connection = current_connections[finger_print]
    for pts in connection["pts"]:
        check_output(["pkill", "-9", "-t", str(pts)])
if __name__ == '__main__':
    app.run()
