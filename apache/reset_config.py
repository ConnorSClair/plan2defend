# Path hack, see https://stackoverflow.com/a/50193944 for a "better alternative"
import os
import pprint
import sys
import subprocess
import logging

sys.path.insert(0, os.path.abspath('..'))

import main

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Delete deny rules
    server_info = main.ServerInfo(main.SERVER_URL, main.TIMEOUT)
    [subprocess.run(main.Acting.get_unblock_ip_command(ip)) for ip in server_info.get_ufw_status()]

    # reset mod_reqtimeout
    original_values = server_info.get_mod_reqtimeout_status()
    target_values = {"header": {"first_byte": 20, "last_byte": 40, "minrate": 500},
                     "body": {"first_byte": 10, "minrate": 500}}
    main.Acting.change_mod_reqtimeout(main.MOD_REQTIMEOUT_PATH, original_values, target_values)
    subprocess.run(main.Acting.get_restart_server_command())
