# external Libraries
from flask import Flask, json, Response, make_response, request, jsonify
import SecAppManager, jwt
# standard Libraries
import re, sys, time
app = Flask(__name__)
secret = "5566F08A9218BEAF6E6714B5870161CBD12A975F6E516FAD66D28FE56302930D"
timeout_length = 5 * 60 # timeout time of token in seconds

@app.route('/')
def home():
    return "Coming soon."

@app.route('/register', methods=['POST'])
def register():
    # Get token from Register Request
    params = request.get_json()
    # Decode token, check if token is not expired and verified.
    payload = jwt.decode(str(params["token"]), secret, algorithms=['HS256'])
    # Payload contains: { "type": "REGISTER", "group": "saGroup", "hw_addr": "mac-address", "misc": "misc info" }
    if(payload["type"] != "REGISTER"):
        raise ValueError("Type of Request not matching URI.")
    # Check if received HW_ADDR is a MAC-Address and create a SecApp Instance
    if len(payload["hw_addr"]) == 17 and re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", payload["hw_addr"]):
        secApp = SecAppManager.Model.SecApp(payload["group"], payload["hw_addr"], payload["misc"])
    else:
        raise ValueError("HW_ADDR is invalid!")
    try:
        # Add SecApp to SecAppManager, error handling
       addSecApp(secApp)
    except ImportWarning as e:
        # If SecApp already registered, send instanceID of that secApp with a 208 Status Code (Already Reported)
        print("Already registered!")
        secApp.instanceID = str(e)
        resp = jsonify({"instanceID": str(e)})
        resp.status_code = 208
    # Create token to verify registration by Controller and send token containing expiration and instanceID to
    # requesting Instance
    encode = jwt.encode({"exp": (int(time.time()+timeout_length)), "instanceID": secApp.instanceID}, secret, algorithm='HS256')
    resp = jsonify({"token": encode.decode("utf-8")})
    resp.status_code = 200
    return resp

@app.route('/keep-alive', methods=['POST'])
def keepAlive():
    # Check if received keep-alive message is valid.
    decoded = checkAuth(request)
    instanceID = decoded["instanceID"]
    group = instanceID.split("-")
    # Check if group of the Security Appliance is available in the SecAppManager.
    if(group[0] not in secApps.keys()):
        return handle_error({"code": "wrapper_group_not_available", "description": "Group of Wrapper Instance not found in SecAppMannager"}, 404)
    found = False
    # Check if instanceID of received keep-alive message is registered.
    for model in secApps[group[0]]:
        if(instanceID == model.instanceID):
            found = True
    # if not registered, send error message
    if(found == False):
        return handle_error({"code": "wrapper_not_registered", "description": "Wrapper Instance not registered in SecAppManager!"}, 404)
    # else send new token!
    encode = jwt.encode({"exp": (int(time.time()+timeout_length)), "instanceID": decoded["instanceID"]}, secret, algorithm='HS256')
    resp = jsonify({"token": encode.decode("utf-8")})
    resp.status_code = 200
    return resp

@app.route('/alert', methods=['POST'])
def alert():
    # TODO: Logic
    if(checkAuth(request) != False):
        resp = jsonify({"route": 'alert'})
        resp.status_code = 200
        return resp

@app.route('/delete', methods=['POST'])
def delete():
    decoded = checkAuth(request)
    instanceID = decoded["instanceID"]
    group = instanceID.split("-")
    if (group[0] not in secApps.keys()):
        return handle_error({"code": "wrapper_group_not_available",
                             "description": "Group of Wrapper Instance not found in SecAppManager"}, 404)
    found = False
    # Check if instanceID of received keep-alive message is registered.
    for model in secApps[group[0]]:
        if (instanceID == model.instanceID):
            delSecApp(model)
    print(secApps[group[0]])
    resp = jsonify({"delete": "true"})
    resp.status_code = 200
    return resp

@app.route('/secapps', methods=['GET'])
def secapps():
    res = ""
    for gr in secApps.keys():
        for app in secApps[gr]:
            res += app.instanceID + ",\n"
    return res



def checkAuth(request):
    # Checks if the token in the Header is signed and not expired.
    # Return payload.
    header = request.headers.get("Authorization")
    print(header)
    if not header:
        return handle_error({"code": "auth_header_missing", "description": "Authorization Header is missing."}, 401)
    split = header.split()

    if (split[0].lower() != "bearer"):
        return handle_error({"code": "invalid_header", "description": "Authorization header must start with 'Bearer'"},
                            401)
    elif (len(split) == 1):
        return handle_error({"code": "invalid_header", "description": "Token not found"}, 401)
    elif (len(split) > 2):
        return handle_error({"code": "invalid_header_format", "description": "Authorization header format is invalid."},
                            401)
    token = split[1]
    try:
        # Check if token is valid.
        payload = jwt.decode(token, secret, leeway=10, algorithms=['HS256'])
    except:
        print("Token is false or expired!")
        return False

    return payload

def handle_error(error, status_code):
    print(error)
    resp = jsonify(error)
    resp.status_code = status_code
    return resp

def addGroup(group):
    secApps[group] = list()
    return True

def addSecApp(secApp):
    # Add Security Appliance to Manager
    if(secApp.group in secApps.keys()):
        if(len(secApps[secApp.group]) == 0):
            secApps[secApp.group].append(secApp)
        else:
            for appliance in secApps[secApp.group]:
                if(appliance.equals(secApp)):
                    raise ImportWarning(appliance.instanceID)
                else:
                    secApps[secApp.group].append(secApp)
                    print(secApps)

def delSecApp(secApp):
    # Delete Security Appliance from Manager.
    if(secApp.group in secApps.keys()):
        if (len(secApps[secApp.group]) == 0):
            print("Group is empty. No Wrapper instances of %s registered.", secApp.group)
        else:
            for appliance in secApps[secApp.group]:
                if (appliance.equals(secApp)):
                    secApps[secApp.group].remove(secApp)
                else:
                    print("Security Appliance with id %s was not registered.", secApp.instanceID)


if(__name__ == "__main__"):
    secApps = dict()
    addGroup("fw")
    addGroup("ddos")
    addGroup("ips")
    app.run(debug=False, host='0.0.0.0', port=5000)