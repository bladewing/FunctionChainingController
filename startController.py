# external Libraries
from flask import Flask, json, Response, make_response, request, jsonify
import SecAppManager
# standard Libraries
import re
app = Flask(__name__)

@app.route('/')
def home():
    return "Coming soon."

@app.route('/register', methods=['POST'])
def register():
    params = request.get_json()
    # { "type": "REGISTER", "group": "saGroup", "hw_addr": "mac-address", "token": "secureToken", "misc": "misc info" }
    if(params["type"] != "REGISTER"):
        raise ValueError("Type of Request not matching URI.")
    if len(params["hw_addr"]) == 17 and re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", params["hw_addr"]):
        secApp = SecAppManager.Model.SecApp(params["group"], params["hw_addr"], params["token"], params["misc"])
    else:
        raise ValueError("HW_ADDR is invalid!")
    try:
       addSecApp(secApp)
    except ImportWarning:
        resp = jsonify({"instanceID": secApp.instanceID})
        resp.status_code = 208
    resp = jsonify({"instanceID": secApp.instanceID})
    resp.status_code = 200
    return resp

@app.route('/keep-alive', methods=['POST'])
def keepAlive():
    resp = jsonify({"route": 'keep-alive'})
    resp.status_code = 200
    return resp

@app.route('/alert', methods=['POST'])
def alert():
    resp = jsonify({"route": 'alert'})
    resp.status_code = 200
    return resp

@app.route('/delete', methods=['POST'])
def delete():
    return 'Hello'

@app.route('/secapps')
def secapps():
    print(str(secApps["fw"]))
    return str(secApps["fw"])

def addGroup(group):
    secApps[group] = list()
    return True

def addSecApp(secApp):
    if(secApp.group in secApps.keys()):
        print(secApps[secApp.group])
        if(len(secApps[secApp.group]) == 0):
            secApps[secApp.group].append(secApp)
        else:
            for appliance in secApps[secApp.group]:
                if(appliance.equals(secApp)):
                    raise ImportWarning("Security Appliance already registered")
                else:
                    secApps[secApp.group].append(secApp)
                    print(secApps)

if(__name__ == "__main__"):
    secApps = dict()
    addGroup("fw")
    addGroup("ddos")
    addGroup("ips")
    app.run(debug=False, host='0.0.0.0', port=5000)