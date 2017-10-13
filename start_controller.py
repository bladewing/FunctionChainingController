""" start controller """
import configparser
import threading

import re
import sys
import time
from urllib.request import Request, urlopen
from flask import Flask, json, request, jsonify, render_template
import SecAppManager
import jwt
import logging
import os

# Initialize and load CONFIG.
CONFIG = configparser.ConfigParser()
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'controller.ini')
CONFIG.read(CONFIG_FILE)
if not CONFIG["GENERAL"]["port"]:
    print("Port missing in Config file!")
    sys.exit(0)
GROUP_LIST = json.loads(CONFIG["Controller"]["groups"])
CONTROLLER_URL = CONFIG["GENERAL"]["SDN_CONTROLLER"]
APP = Flask(__name__)
if not CONFIG["GENERAL"]["SECRET"]:
    print("Secret missing in Config file!")
    sys.exit(0)
SECRET = CONFIG["GENERAL"]["SECRET"]
if not CONFIG["Controller"]["timeout"]:
    print("Timeout missing in Config file!")
    sys.exit(0)
TIMEOUT_LENGTH = int(CONFIG["Controller"]["timeout"]) * 60  # timeout time of token in minutes
global CONTROLLER_READY
STANDARD_CONF = json.loads(CONFIG["Controller"]["standard_conf"])
global CURRENT_CONF
THRESHHOLD = 100
ATTACK_LIST = dict()
for grp in GROUP_LIST:
    ATTACK_LIST["%s" % (grp)] = 0


@APP.route('/')
def home():
    """ Render template to show user interface. """
    return render_template('index.html',
                           ATTACK_LIST=([(k, ATTACK_LIST[k]) for k in sorted(ATTACK_LIST, key=ATTACK_LIST.get, reverse=True)]), current_conf=CURRENT_CONF,
                           standard_conf=STANDARD_CONF, SECAPP_COUNT=len(STANDARD_CONF))


@APP.route('/handle_data', methods=["POST"])
def handle_data():
    LOGGER.info("[HANDLE_DATA] Incoming change request from /")
    global CURRENT_CONF
    new_conf = dict(request.form)["secapps"]
    new_conf_set = set(new_conf)
    if len(new_conf_set) < len(STANDARD_CONF):
        LOGGER.error("[HANDLE_DATA] New configuration has at least two SecApps of the same"
                     "group in list. ", new_conf)
        return render_template('change.html', success=False, conf=new_conf, current=CURRENT_CONF    )
    if new_conf == CURRENT_CONF:
        LOGGER.error("[HANDLE_DATA] Current Configuration equals requested change.")
        return render_template('change.html', success=False, conf=new_conf, current=CURRENT_CONF)
    new_conf.insert(0, "ingress")
    data = {"list": json.dumps(new_conf)}
    data_json = json.dumps(data)
    LOGGER.info("[HANDLE_DATA] Sending modified configuration to SDN Controller...")
    conn = Request(CONTROLLER_URL + "/mod_routing",
                   data_json.encode("utf-8"),
                   {'Content-Type': 'application/json'})
    new_conf.pop(0)
    resp = urlopen(conn)
    LOGGER.info("[HANDLE_DATA] Modified configuration sent successfully.")
    CURRENT_CONF = new_conf
    return render_template('change.html', success=True, conf=CURRENT_CONF, resp_code=resp.getcode(),
                           SECAPP_COUNT=len(STANDARD_CONF))


@APP.route('/register', methods=['POST'])
def register():
    """
    Registers Security Appliances and sends instance_id back in response with token.
    :return:
    """
    # Get token from Register Request
    LOGGER.info("[REGISTER] Incoming registration request.")
    params = request.get_json()
    # Decode token, check if token is not expired and verified.
    payload = jwt.decode(str(params["token"]), SECRET, algorithms=['HS256'])
    # Payload contains: { "type": "REGISTER", "group": "saGroup", "hw_addr": "mac-address",
    # "misc": "misc info" }
    if payload["type"] != "REGISTER":
        LOGGER.error("[REGISTER] Type of request not matching URI!")
        raise ValueError("Type of Request not matching URI.")
    # Check if received HW_ADDR is a MAC-Address and create a SecApp Instance
    if len(payload["hw_addr"]) == 17 and re.match(
            "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", payload["hw_addr"]):
        sec_app = SecAppManager.Model.SecApp(payload["group"], payload["hw_addr"], payload["misc"])
    else:
        LOGGER.error("[REGISTER] HW_ADDR is invalid. ", payload["hw_addr"])
        raise ValueError("HW_ADDR is invalid!")
    try:
        # Add SecApp to SecAppManager, error handling
        add_sec_app(sec_app)
    except ImportWarning as import_warning:
        # If SecApp already registered, send instance_id of that sec_app with a 208 Status Code (
        # Already Reported)
        LOGGER.info("[REGISTER] SecApp already registered! Sending token and ID...")
        sec_app.instance_id = str(import_warning)
        encode = jwt.encode({"exp": (int(time.time() + TIMEOUT_LENGTH)),
                             "instance_id": sec_app.instance_id}, SECRET, algorithm='HS256')
        resp = jsonify({"token": encode.decode("utf-8")})
        resp.status_code = 208
        return resp
    # Create token to verify registration by Controller and send token containing expiration and
    # instance_id to requesting Instance
    encode = jwt.encode(
        {"exp": (int(time.time() + TIMEOUT_LENGTH)), "instance_id": sec_app.instance_id}, SECRET,
        algorithm='HS256')
    resp = jsonify({"token": encode.decode("utf-8")})
    resp.status_code = 200
    LOGGER.info("[REGISTER] Token sent via Response!")
    return resp


@APP.route('/keep-alive', methods=['POST'])
def keep_alive():
    """
    If SecApp is registered, return a new token
    :return:
    """
    # TODO: If Controller is restarted and keep-alive comes in, re-register Wrapper if request is
    #  valid
    # Check if received keep-alive message is valid.
    LOGGER.info("[KEEP-ALIVE] Incoming Keep-Alive message")
    decoded = check_auth(request)
    if not decoded:
        # Token Expired
        LOGGER.error("[KEEP-ALIVE] Token expired.")
        return handle_error({"code": "token_expired", "description": "Token expired!"}, 401)
    instance_id = decoded["instance_id"]
    ka_group = instance_id.split("-")
    # Check if group of the Security Appliance is available in the SecAppManager.
    if ka_group[0] not in SEC_APP_DICT.keys():
        LOGGER.error("[KEEP-ALIVE] Wrapper group not available: Group is not in config file. Check"
                     "\"controller.ini\".")
        return handle_error({"code": "wrapper_group_not_available", "description":
            "Group of Wrapper Instance not found in SecAppMannager"}, 404)
    found = False
    # Check if instance_id of received keep-alive message is registered.
    for model in SEC_APP_DICT[ka_group[0]]:
        if instance_id == model.instance_id:
            found = True
    # if not registered, send error message
    if not found:
        LOGGER.error("[KEEP-ALIVE] Wrapper not registered. Instance not in SecAppManager.")
        return handle_error({"code": "wrapper_not_registered",
                             "description": "Wrapper Instance not registered in SecAppManager!"},
                            404)
    # else send new token!
    LOGGER.info("[KEEP-ALIVE] Sending new token to %s..."%(decoded["instance_id"]))
    encode = jwt.encode(
        {"exp": (int(time.time() + TIMEOUT_LENGTH)), "instance_id": decoded["instance_id"]}, SECRET,
        algorithm='HS256')
    resp = jsonify({"token": encode.decode("utf-8")})
    resp.status_code = 200
    LOGGER.info("[KEEP-ALIVE] Token updated for %s"%(decoded["instance_id"]))
    return resp


@APP.route('/alert', methods=['POST'])
def alert():
    """
    Maintains list of SecApps and their attacks.
    :return:
    """
    LOGGER.info("[ALERT] Incoming attack message...")
    decoded = check_auth(request)
    if not decoded:
        # Token Expired
        LOGGER.error("[ALERT] Token expired!")
        return handle_error({"code": "token_expired", "description": "Token expired!"}, 401)
    data = request.json
    ATTACK_LIST[data["group"]] += int(data["rate"])
    resp = jsonify({"route": 'alert'})
    resp.status_code = 200
    LOGGER.info("[ALERT] ATTACK_LIST is updated!")
    return resp


@APP.route('/delete', methods=['POST'])
def delete():
    """
    Delete a SecApp from List.
    :return:
    """
    LOGGER.info("[DELETE] Incoming delete message...")
    decoded = check_auth(request)
    if not decoded:
        # Token Expired
        LOGGER.error("[DELETE] Token expired!")
        return handle_error({"code": "token_expired", "description": "Token expired!"}, 401)
    instance_id = decoded["instance_id"]
    LOGGER.info("[DELETE] Removing ",instance_id)
    del_group = instance_id.split("-")
    if del_group[0] not in SEC_APP_DICT.keys():
        LOGGER.error("[DELETE] Group of %s not available. Check \"controller.ini\"... "%(instance_id))
        return handle_error({"code": "wrapper_group_not_available",
                             "description": "Group of Wrapper Instance not found in SecAppManager"},
                            404)
    # Check if instance_id of received keep-alive message is registered.
    for model in SEC_APP_DICT[del_group[0]]:
        if instance_id == model.instance_id:
            del_sec_app(model)
            LOGGER.info("[DELETE] Removed %s!"%(instance_id))
    resp = jsonify({"delete": "true"})
    resp.status_code = 200
    return resp


@APP.route('/secapps', methods=['GET'])
def secapps():
    """
    Shows instance_id's of currently registered SecApps
    :return:
    """
    res = ""
    for grp in SEC_APP_DICT.keys():
        for sec_app in SEC_APP_DICT[grp]:
            res += sec_app.instance_id + ",\n"
    return res


def check_auth(req):
    """
    Checks if the token in the Header is signed and not expired.
    :param request:
    :return:
    """
    header = req.headers.get("Authorization")
    if not header:
        LOGGER.error("[CHECK_AUTH] Auth header is missing!")
        return handle_error(
            {"code": "auth_header_missing", "description": "Authorization Header is missing."}, 401)
    split = header.split()
    len_split = len(split)

    if split[0].lower() != "bearer":
        LOGGER.error("[CHECK_AUTH] Invalid header! Header must start with 'Bearer'")
        return handle_error({"code": "invalid_header",
                             "description": "Authorization header must start with 'Bearer'"},
                            401)
    elif len_split == 1:
        LOGGER.error("[CHECK_AUTH]  Invalid header! Token missing.")
        return handle_error({"code": "invalid_header", "description": "Token not found"}, 401)
    elif len_split > 2:
        LOGGER.error("[CHECK_AUTH] Invalid header format. Authorization header format is invalid.")
        return handle_error({"code": "invalid_header_format",
                             "description": "Authorization header format is invalid."},
                            401)
    token = split[1]
    try:
        # Check if token is valid.
        payload = jwt.decode(token, SECRET, leeway=10, algorithms=['HS256'])
    except:
        LOGGER.error("[CHECK_AUTH] Token invalid or wrong.")
        return False

    return payload


def handle_error(error, status_code):
    """
    Create a JSON Response with error and status_code
    :param error:
    :param status_code:
    :return:
    """
    print(error)
    resp = jsonify(error)
    resp.status_code = status_code
    return resp


def add_group(grp):
    """
    Add SecApp Group to Dict.
    :param grp:
    :return:
    """
    LOGGER.info("[SecAppManager] Adding group %s"%(grp))
    SEC_APP_DICT[grp] = list()
    return True


def add_sec_app(sec_app):
    """
    Add Security Appliance to Manager.
    :param sec_app:
    :return:
    """
    LOGGER.info("[SecAppManager] Adding ",sec_app.instance_id)
    if sec_app.group in SEC_APP_DICT.keys():
        if len(SEC_APP_DICT[sec_app.group]) == 0:
            SEC_APP_DICT[sec_app.group].append(sec_app)
        else:
            for appliance in SEC_APP_DICT[sec_app.group]:
                if appliance.equals(sec_app):
                    LOGGER.error("[SecAppManager] %s already registered!" %(appliance.instance_id))
                    raise ImportWarning(appliance.instance_id)
                else:
                    SEC_APP_DICT[sec_app.group].append(sec_app)
                    LOGGER.info("[SecAppManager] Added ", sec_app.instance_id)


def del_sec_app(sec_app):
    """
    Delete Security Appliance from Manager.
    :param sec_app:
    :return:
    """
    if sec_app.group in SEC_APP_DICT.keys():
        if len(SEC_APP_DICT[sec_app.group]) == 0:
            LOGGER.error("[SecAppManager] Group of %s is empty."%(sec_app.group))
            print("Group is empty. No Wrapper instances of %s registered.", sec_app.group)
        else:
            for appliance in SEC_APP_DICT[sec_app.group]:
                if appliance.equals(sec_app):
                    SEC_APP_DICT[sec_app.group].remove(sec_app)
                    LOGGER.info("[SecAppManager] Removed ", sec_app.instance_id)
                else:
                    LOGGER.info("[SecAppManager] %s not registered!"%(sec_app.instance_id))
                    print("Security Appliance with id %s was not registered.", sec_app.instance_id)


@APP.route('/routing')
def routing():
    """
        Logic of controller. Responsible for chaining the SecApps in correct order, depending on
        attack rate
        :return:
    """
    global CURRENT_CONF
    split_count = 0
    max_splits = TIMEOUT_LENGTH / 10
    while CONTROLLER_READY:
        if split_count < max_splits:
            split_count += 1
            time.sleep(10)
            continue
        CURRENT_CONF = STANDARD_CONF
        split_count = 0
        sorted_attack_list = sorted(ATTACK_LIST, key=ATTACK_LIST.__getitem__, reverse=True)
        if sorted_attack_list == CURRENT_CONF:
            LOGGER.info("[ROUTING] New configuration equals current one.")
            continue
        if ATTACK_LIST[sorted_attack_list[0]] >= THRESHHOLD:
            print("attacks over threshhold. Proceeding...")
            LOGGER.info("[ROUTING] Attack rate over threshhold. Proceding...")
            LOGGER.info("[ROUTING] Updating CURRENT_CONF with ", sorted_attack_list)
            CURRENT_CONF = sorted_attack_list
            sorted_attack_list.insert(0, "ingress")
            data = {"list": json.dumps(sorted_attack_list)}
            data_json = json.dumps(data)
            conn = Request(CONTROLLER_URL + "/mod_routing",
                           data_json.encode("utf-8"),
                           {'Content-Type': 'application/json'})
            resp = urlopen(conn)
        else:
            LOGGER.info("[ROUTING] Attack rate is not over threshhold.")
        # Reset after changing route
        LOGGER.info("[ROUTING] Resetting attack count in ATTACK_LIST.")
        for grp in GROUP_LIST:
            ATTACK_LIST["%s" % (grp)] = 0


@APP.route('/stats')
def stats():
    """
    Returns ATTACK_LIST for statistics.
    :return:
    """
    return str(ATTACK_LIST)


if __name__ == "__main__":
    # Create LOGGER
    LOGGER = logging.getLogger('FCC')
    LOGGER.setLevel(logging.INFO)
    # Create FileHandler to save logs in File.
    LOG_FILE = 'fcc.log'
    FILE_HANDLER = logging.FileHandler(LOG_FILE)
    # Format LOGGER
    LOGGER_FORMATTER = logging.Formatter('%(asctime)s <%(name)s> - <%(levelname)s> : %(message)s')
    FILE_HANDLER.setFormatter(LOGGER_FORMATTER)
    LOGGER.addHandler(FILE_HANDLER)
    # Adding FileHandler to LOGGER of Flask App to merge log files.
    APP.logger.addHandler(FILE_HANDLER)
    SEC_APP_DICT = dict()
    CURRENT_CONF = STANDARD_CONF
    CONTROLLER_READY = True
    thread1 = threading.Thread(target=routing)
    thread1.setDaemon(True)
    thread1.start()
    for group in GROUP_LIST:
        add_group(group)
    try:
        APP.run(debug=False, host='0.0.0.0', port=int(CONFIG["GENERAL"]["port"]))
    except OSError:
        LOGGER.info("[CONTROLLER] Flask Port %s already in use! Check configuration."
                    %(CONFIG["GENERAL"]["port"]))
        sys.exit(0)
