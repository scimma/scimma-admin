import configparser
import os


FILENAME = "localdev.conf"


def main():
    cp = configparser.ConfigParser()
    cp["secrets"] = {
        "cilogon_client_secret": os.env["CILOGON_CLIENT_SECRET"],
    }
    with open(FILENAME, "w") as f:
        cp.write(f)


if __name__ == "__main__":
    main()
