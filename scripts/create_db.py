import argparse
import subprocess
import logging


def main():
    args = parse_args()
    if args.with_docker:
        create_with_docker()
    else:
        create_without_docker(args.dbdata)



def parse_args():
    parser = argparse.ArgumentParser(
        prog="create_db.py",
    )
    parser.add_argument("--with-docker", action="store_true", help="create database in a docker image")
    parser.add_argument("--dbdata", type=str, help="directory to hold database data (only used if not using docker)", default="./dbdata")
    return parser.parse_args()


def create_with_docker():
    subprocess.run([
        "docker", "create",
        "--name=scimma-admin-postgres",
        "--env=POSTGRES_DB=postgres",
        "--env=POSTGRES_PASSWORD=postgres",
        "--env=POSTGRES_USER=postgres",
        "--publish=5432:5432",
        "postgres",
    ])
    subprocess.run([
        "docker", "start", "scimma-admin-postgres",
    ])

def create_without_docker(dbdata_dir):
    subprocess.run(["initdb", "-D", dbdata_dir])
    subprocess.run(["pg_ctl", "-D", dbdata_dir, "-l", "pg_logfile", "start"])
    subprocess.run([
        "psql",
        "--command=CREATE ROLE postgres;",
        "--dbname=postgres",
    ])
    subprocess.run([
        "psql",
        "--command=ALTER ROLE postgres WITH PASSWORD 'postgres';",
        "--dbname=postgres",
    ])
    subprocess.run([
        "psql",
        "--command=ALTER ROLE postgres LOGIN;",
        "--dbname=postgres",
    ])
    pass

if __name__ == "__main__":
    main()
