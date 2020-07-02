import boto3
import configparser

FILENAME = "localdev.conf"


def get_secret(name):
    sm = boto3.client("secretsmanager")
    return sm.get_secret_value(SecretId=name)["SecretString"]


def main():
    cp = configparser.ConfigParser()
    cp["secrets"] = {
        "cilogon_client_secret": get_secret("scimma-admin-cilogon-localdev-client-secret")
    }
    with open(FILENAME, "w") as f:
        cp.write(f)


if __name__ == "__main__":
    main()
