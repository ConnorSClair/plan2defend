import logging
import copy
import json

import requests
import subprocess
import time

# requirements
import re
import pprint
import apache_log_parser
import pandas as pd
import matplotlib.pyplot as plt
from pandas.plotting import register_matplotlib_converters
from jinja2 import Environment, FileSystemLoader

LINE_PARSER = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"")

# TODO: move hardcoded values to plan2defend.conf 
TIMEOUT = 15
LOG_TAIL_UPPER_LIMIT = 500
SLEEP_TIME = 0
REQUESTS_PER_MINUTE_THRESHOLD = 120
WAIT_TIME = 15
IDLE_WORKERS_THRESHOLD = 0.1
SLOWEST_ACCEPTABLE_REQUEST_TIME = 6
STATE_SLEEP_TIME = 4

DOMAIN_NAME = "website"
PROBLEM_NAME = "p0"
SERVER_NAME = "apache2"
MOD_REQTIMEOUT_PATH = "/etc/apache2/mods-enabled/reqtimeout.conf"
LOG_PATH = "/var/log/apache2/access.log"
SERVER_URL = "URL-HERE"
CONFIGURATION_FILE_PATH = "plan2defend.conf"
ORIGINAL_MOD_REQTIMEOUT_VALUES = {"header": {"first_byte": 20, "last_byte": 40, "minrate": 500}, "body": {"first_byte": 10, "minrate": 500}}
SHORT_WAIT_MOD_REQTIMEOUT_VALUES = {"header": {"first_byte": 4, "last_byte": 8, "minrate": 1000}, "body": {"first_byte": 10, "minrate": 500}}


class BusinessInfo:

    def __init__(self):
        pass

    def get_business_metrics(self):
        # hardcoded
        return {
            "expected_revenue": 500,
            "revenue_impact": 100,
            "slow_connection_users": 50,
            "total-cost": 0,
            "restart_cost": 50,
            "sysadmin_cost": 1000
        }


class RequestInfo:

    def __init__(self, path_to_log_file, log_tail_upper_limit):
        register_matplotlib_converters()
        self.path_to_log_file = path_to_log_file
        if log_tail_upper_limit < 0:
            raise ValueError(f"log_tail_upper_limit must be >= 0")
        self.log_tail_upper_limit = log_tail_upper_limit

    def __get_parsed_server_log(self):
        # preferably: more efficiently read the tail of a file by using seek()
        with open(self.path_to_log_file, "r") as f:
            reversed_f = reversed(f.readlines())
            result = []
            for _ in range(self.log_tail_upper_limit):
                try:
                    line = next(reversed_f).strip()
                except StopIteration:
                    break
                result.append(LINE_PARSER(line))
            return result

    def get_requests_per_minute(self):
        """
        :return: Dict[str, Dict[datetime, int]]
        """
        result = {}
        logs = self.__get_parsed_server_log()
        for log in logs:
            remote_host = log["remote_host"]
            if remote_host not in result:
                result[remote_host] = {}
            date_time = log["time_received_datetimeobj"]
            on_minute = date_time.replace(second=0)
            for minute in [(on_minute.minute - 1) % 60, on_minute.minute, (on_minute.minute + 1) % 60]:
                # for graphing purposes
                other = on_minute.replace(minute=minute)
                if other not in result[remote_host]:
                    result[remote_host][other] = 0
            result[remote_host][on_minute] += 1
        return result

    def plot_requests(self):
        # TODO: add labels, etc. to plot
        requests_per_minute = self.get_requests_per_minute()
        dataframes = {ip: None for ip in requests_per_minute.keys()}
        plt.figure()
        for ip in requests_per_minute.keys():
            data = [[key, value] for key, value in requests_per_minute[ip].items()]
            dataframes[ip] = pd.DataFrame(data, columns=["time", "count"])
            plt.scatter(dataframes[ip]["time"], dataframes[ip]["count"], label=ip)
        plt.legend()
        plt.show()


class ServerInfo:

    def __init__(self, server_url, timeout):
        self.server_url = server_url
        self.mod_reqtimeout_path = MOD_REQTIMEOUT_PATH
        if timeout <= 0:
            raise ValueError(f"timeout must be > 0")
        self.timeout = timeout

    def __get_server_status(self):
        response = requests.get(self.server_url + "/server-status?auto", timeout=self.timeout)
        response_text = response.text.split("\n")
        result = {}
        for line_number, line in enumerate(response_text):
            if line_number == 0 or line_number == len(response_text) - 1:
                continue
            key, value = line.split(": ")
            result[key] = value
        return result, response.elapsed.total_seconds()

    def get_ufw_status(self):
        command = ["sudo", "ufw", "status"]
        p = subprocess.Popen(command, stdout=subprocess.PIPE)
        status_lines = p.stdout.read().decode('ascii').split("\n")
        result = []
        for line in status_lines:
            line = line.split()
            if len(line) == 3 and line[1] == "DENY":
                result.append(line[2])
        return result

    def get_mod_reqtimeout_status(self):
        with open(self.mod_reqtimeout_path, "r") as f:
            header_match = "RequestReadTimeout header=[0-9]*-[0-9]*,minrate=[0-9]*."
            body_match = "RequestReadTimeout body=[0-9]*,minrate=[0-9]*."

            lines = f.read()

            before_headers = re.search(header_match, lines).group()
            header = []
            _, vals = re.search("header=[0-9]*-[0-9]*", before_headers).group().split("=")
            header.extend([int(x) for x in vals.split("-")])
            header.append(int(re.search("minrate=[0-9]*.", before_headers).group().split("=")[1]))

            body = []
            before_body = re.search(body_match, lines).group()
            _, val = re.search("body=[0-9]*", before_body).group().split("=")
            body.append(int(val))
            body.append(int(re.search("minrate=[0-9]*.", before_body).group().split("=")[1]))

            result = {"header": {"first_byte": header[0], "last_byte": header[1], "minrate": header[2]},
                      "body": {"first_byte": body[0], "minrate": body[1]}, "changed": header[0] < 10}
            return result

    def get_server_metrics(self):
        """ Throws requests.exceptions.ConnectTimeout upon connection timeout. """
        blocked = self.get_ufw_status()
        mod_reqtimeout_status = self.get_mod_reqtimeout_status()
        try:
            server_status, response_time = self.__get_server_status()

            return {"service_unreachable": False,
                    "idle_workers": int(server_status["IdleWorkers"]),
                    "busy_workers": int(server_status["BusyWorkers"]),
                    "CPU_system": float(server_status["CPUSystem"]),
                    "blocked": blocked,
                    "request_read_timeout": mod_reqtimeout_status,
                    "response_time": response_time}
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
            return {"service_unreachable": True,
                    "idle_workers": None,
                    "busy_workers": None,
                    "CPU_system": None,
                    "blocked": blocked,
                    "request_read_timeout": mod_reqtimeout_status,
                    "response_time": 100}


class StateInfo:

    def __init__(self, path_to_log_file, server_url, path_to_configuration_file):
        self.server_info = ServerInfo(server_url, TIMEOUT)
        self.request_info = RequestInfo(path_to_log_file, LOG_TAIL_UPPER_LIMIT)
        self.business_info = BusinessInfo()

        self.state = {"server_name": SERVER_NAME}

        # initialise state values
        self.update_request_info()
        self.update_server_status()
        self.update_business_impacts()

    def update_state(self):
        self.update_request_info()
        self.update_server_status()
        self.update_business_impacts()

    def update_request_info(self):
        self.state["requests_per_minute"] = self.request_info.get_requests_per_minute()

    def update_server_status(self):
        self.state.update(self.server_info.get_server_metrics())

    def update_business_impacts(self):
        self.state["business_metrics"] = self.business_info.get_business_metrics()

    def get_state(self):
        return copy.deepcopy(self.state)

    def to_json(self, filename):
        # for debugging
        with open("filename" + ".json", "w") as f:
            json.dump(self.state, f)

    def __repr__(self):
        return str(vars(self))

    def __str__(self):
        return self.__repr__()


class Planning:

    @staticmethod
    def __get_static_problem_info():
        result = {}
        result["domain"] = DOMAIN_NAME
        result["name"] = PROBLEM_NAME
        result["objects"] = {}
        result["objects"]["servers"] = [{"name": SERVER_NAME}]
        result["objects"]["ips"] = []
        result["predicates"] = []
        result["goal"] = []
        return result

    @staticmethod
    def state_to_problem_info(state):
        requests_per_minute = state["requests_per_minute"]

        # static info
        result = Planning.__get_static_problem_info()

        # ip info
        for i, ip in enumerate(requests_per_minute.keys()):
            peak = 0
            for count in requests_per_minute[ip].values():
                peak = max(peak, count)
            result["objects"]["ips"].append({"name": f"ip{i}", "addr": ip, "peak_requests_per_minute": peak})

            if peak >= REQUESTS_PER_MINUTE_THRESHOLD:
                if ip != "192.168.23.140":
                    result["predicates"].append(["REQUEST_RATE_HIGH_FROM_IP", f"ip{i}"])
            if ip in state["blocked"]:
                result["predicates"].append(["BLOCKED", f"ip{i}"])

    
        # server info
        if state["service_unreachable"]:
            result["predicates"].append(["SERVICE_UNREACHABLE", state["server_name"]])
            result["predicates"].append(["SERVICE_SLOW", state["server_name"]])
        else:
            idle_workers = float(state["idle_workers"])
            busy_workers = int(state["busy_workers"])
            idle_workers_proportion = idle_workers / (idle_workers + busy_workers)
            if idle_workers_proportion < IDLE_WORKERS_THRESHOLD:
                # TODO: change this to "service under heavy load" or something.
                result["predicates"].append(["SERVICE_UNREACHABLE", state["server_name"]])
            if state["response_time"] > SLOWEST_ACCEPTABLE_REQUEST_TIME:
                result["predicates"].append(["SERVICE_SLOW", state["server_name"]])
        if state["request_read_timeout"]["changed"]:
            result["predicates"].append(["REQUEST_HEADER_TIMEOUT_FAST", state["server_name"]])

        # business impacts
        result["function_values"] = [[k.upper(), state["business_metrics"][k]] for k in
                                     state["business_metrics"].keys()]

        # for debugging
        with open("pddl/problem_info.json", "w") as f:
            json.dump(result, f)

        return copy.deepcopy(result)

    @staticmethod
    def render_problem(problem_info):
        # preferably: load the template from disc once, rather than every time
        data = problem_info

        file_loader = FileSystemLoader('.')
        env = Environment(loader=file_loader)
        env.trim_blocks = True
        env.lstrip_blocks = True
        env.rstrip_blocks = True

        template = env.get_template('problem-template-basic.pddl')
        result = template.render(data=data)
        with open("pddl/p-basic.pddl", "w") as f:
            f.write(result)

        return result

    @staticmethod
    def __get_verbose_plan():
        command = ['pddl/ff', '-o', 'pddl/d-basic.pddl', '-f', 'pddl/p-basic.pddl', '-O']
        proc = subprocess.Popen(command, stdout=subprocess.PIPE)
        verbose_plan = proc.stdout.read().decode('UTF-8').split("\n")

        with open("pddl/out.txt", "w") as f:
            f.write('\n'.join(verbose_plan) + '\n')

        return verbose_plan

    @staticmethod
    def parse_verbose_plan(verbose_plan):
        result = []
        solution_line = False
        for line in verbose_plan:
            line = line.strip(" ")
            if line.startswith("step"):
                solution_line = True
                line = line[8:]
            if line == "":
                solution_line = False
            if solution_line:
                _, line = line.split(":")
                line = line.strip()
                result.append(line)
        return [line.split(" ") for line in result]

    @staticmethod
    def get_plan():
        plan = Planning.parse_verbose_plan(Planning.__get_verbose_plan())
        # for debugging
        with open("pddl/plan.txt", "w") as f:
            for step in plan:
                f.write(" ".join(step) + '\n')
        return plan


class Acting:

    @staticmethod
    def do_plan(plan, state, problem_info):
        for step in plan:
            Acting.do_action(step[0], step[1:], state, problem_info)

    @staticmethod
    def do_action(action, affected_objects, state, problem_info):
        if action == "REACH-GOAL":
            return
        elif action == "RESTART_SERVER":
            command = Acting.get_restart_server_command()
        elif action == "BLOCK_IP":
            ip = affected_objects[0]
            command = Acting.get_block_ip_command(Acting.get_ip_addr(ip, problem_info))
        elif action == "UNBLOCK_IP":
            ip = affected_objects[0]
            command = Acting.get_unblock_ip_command(Acting.get_ip_addr(ip, problem_info))
        else:
            if action == "DECREASE_REQUEST_HEADER_TIMEOUT":
                Acting.change_mod_reqtimeout(MOD_REQTIMEOUT_PATH,ORIGINAL_MOD_REQTIMEOUT_VALUES,
                                             SHORT_WAIT_MOD_REQTIMEOUT_VALUES)
            elif action == "INCREASE_REQUEST_TIMEOUT":
                Acting.change_mod_reqtimeout(MOD_REQTIMEOUT_PATH,SHORT_WAIT_MOD_REQTIMEOUT_VALUES,
                                             ORIGINAL_MOD_REQTIMEOUT_VALUES)
            return
        logging.info(f"Running Command: {' '.join(command)}")
        subprocess.run(command)

    @staticmethod
    def get_ip_addr(ip, problem_info):
        ip = ip.lower()
        ips = problem_info['objects']['ips']
        result = ""
        for ip_obj in ips:
            if ip_obj['name'] == ip:
                result = ip_obj['addr']
        return result


    @staticmethod
    def change_mod_reqtimeout(reqtimeout_path, original_values, target_values):

        low = original_values["header"]["first_byte"]
        high = original_values["header"]["last_byte"]
        minrate = original_values["header"]["minrate"]

        header_before = f"RequestReadTimeout header={low}-{high},minrate={minrate}"

        low = target_values["header"]["first_byte"]
        high = target_values["header"]["last_byte"]
        minrate = target_values["header"]["minrate"]

        header_after = f"RequestReadTimeout header={low}-{high},minrate={minrate}"
        
        command = ['sudo', 'sed', '-i', f"s/{header_before}/{header_after}/", f"{reqtimeout_path}"]
        logging.info(f"\nbefore: \t{header_before}\nafter: \t\t{header_after}")
        subprocess.run(command)

    @staticmethod
    def get_restart_server_command():
        return ["sudo", "systemctl", "restart", "apache2"]

    @staticmethod
    def get_block_ip_command(ip_addr):
        return ["sudo", "ufw", "insert", "1", "deny", "from", ip_addr, "to", "any"]

    @staticmethod
    def get_unblock_ip_command(ip_addr):
        return ["sudo", "ufw", "delete", "deny", "from", ip_addr, "to", "any"]


class Controller:

    def __init__(self):
        self.state_info = StateInfo(LOG_PATH, SERVER_URL, CONFIGURATION_FILE_PATH)

    def respond(self, state):
        logging.info(f"Translating the state into PDDL problem data...")
        problem_info = Planning.state_to_problem_info(state)
        time.sleep(SLEEP_TIME)
        logging.info(f"Problem Info: \n{pprint.pformat(problem_info)}\n")
        problem = Planning.render_problem(problem_info)
        logging.info(f"PDDL Problem File: \n{problem}\n")
        time.sleep(SLEEP_TIME)
        logging.info(f"Running Planner...")
        plan = Planning.get_plan()
        logging.info(f"Plan Found: \n{pprint.pformat(plan)}\n")
        Acting.do_plan(plan, state, problem_info)

    def is_incident_occuring(self, state):
        if state["response_time"] > SLOWEST_ACCEPTABLE_REQUEST_TIME:
            logging.info(f"An incident appears to be occuring as service is too slow.")
            return True

        if state["service_unreachable"]:
            logging.info(f"An incident appears to be occuring as service is unreachable.")
            return True
        idle_workers = float(state["idle_workers"])
        busy_workers = int(state["busy_workers"])
        idle_workers_proportion = idle_workers / (idle_workers + busy_workers)
        if idle_workers_proportion < IDLE_WORKERS_THRESHOLD:
            logging.info(f"An incident appears to be occuring as nearly all workers are busy.")
            return True
        return False

    def run(self):
        while True:
            logging.info(f"Getting updated state information...")
            time.sleep(SLEEP_TIME)
            self.state_info.update_state()
            state = self.state_info.get_state()
            logging.info(f"State: \n{pprint.pformat(state)}\n")
            if self.is_incident_occuring(state):
                time.sleep(SLEEP_TIME)
                self.respond(state)
                logging.info(f"Waiting {WAIT_TIME} seconds for actions to take effect...")
                time.sleep(WAIT_TIME)
            else:
                logging.info(f"Sleeping for {STATE_SLEEP_TIME} seconds to allow for state to change...")
                time.sleep(STATE_SLEEP_TIME)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    controller = Controller()
    controller.run()
