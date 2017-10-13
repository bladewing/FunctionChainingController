"""
Simple Wrapper for a Simple SDN Controller.
"""
from flask import Flask, make_response, request
import os
local_ip = "10.1.3.39"
app = Flask(__name__)

@app.route('/rules', methods=['POST'])
def rules():
    loaded = request.json
    rules_file = open('new_rules.sh', 'w')
    rules_file.write("#!/bin/sh\n")
    for i in range(0,len(loaded[local_ip])):
       rules_file.write("ovs-ofctl add-flow br0 \"%s\""%(loaded[local_ip][i])+"\n")
    rules_file.close()
    os.system('chmod +x new_rules.sh && ./rules.sh && ./new_rules.sh')

    return make_response("test",200)

if(__name__ == "__main__"):
    app.run(debug=False, host='0.0.0.0', port=5051)