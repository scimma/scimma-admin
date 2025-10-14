"""
Draw data from
- Scmma-admin  (topics, groups, topic descripton)
- Archive "how recent", public/private

Combine and arrange into a model for a web page.
"""

import argparse
import logging
import datetime
import json
import boto3
import psycopg2
from botocore.exceptions import ClientError
#import hop
import os
import time
import pprint
import django
from functools import wraps

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)
log_format='[%(asctime)s] %(name)s %(levelname)s %(message)s'
formatter = logging.Formatter(log_format, datefmt='%d/%B/%Y %H:%M:%S,%3d')
stream_handler.setFormatter(formatter)

from django.apps import apps

##################################################
#
# Utilities
#
##################################################


def time_me(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        elapsed = end_time - start_time
        logging.info(f"Function '{func.__name__}' executed in {elapsed:.6f} seconds")
        return result
    return wrapper

@time_me
def get_secret(args, secret_name):
    region_name = args["aws_region"]
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    secret_value_response = client.get_secret_value(
        SecretId=secret_name
    )
    return secret_value_response["SecretString"]


@time_me
def get_rds_db(db_instance_id):
#    rds = boto3.client("rds", region_name="us-west-2")
    rds = boto3.client("rds")
    resp = rds.describe_db_instances(Filters=[
        {"Name": "db-instance-id", "Values": [db_instance_id]},
    ])
    return resp['DBInstances'][0]

###
### Configuration section
###

#
#  Search the environment for overrides.
#

#########################
###
### Configuration Section
###
#########################

args = {}
prefix="RECENT_"           # environment vars begin with this
args['loglevel'] = 'INFO'  #
args['days_recent']  = 90  # Recent if within the past few days 
args['aws_region'] = 'us-west-2'


# Tunnel specific parameteter
args['remote_tunnel']  = os.getenv('REMOTE_TUNNEL')

if args['remote_tunnel'] :
    args['tunnel_archive_local_port'] = os.getenv('ARCHIVE_LOCAL_PORT')
    args['tunnel_ssh_username'] = os.getenv('REMOTE_USER')
    args['tunnel_ssh_pkey'] = '/Users/donaldp/.ssh/id_rsa'
    args['tunnel_ssh_admin_host'] = os.getenv('ADMIN_HOST')

# Archive connect info #
args['archive_db_instance'] = os.getenv('ARCHIVE_DB_INSTANCE') 
args['archive_db_secretname'] = os.getenv('ARCHIVE_DB_SECRET_NAME')

# Provide for type conversion/casting
def bool_caster(text: str) -> bool :
    if text == "True" : return True
    if text == "False": return False
    throw (f"value must be exactly True of False, got {text}")
    
casters = {type("a"):str, type(1) :int, type (1.0):float, type(True):bool_caster}

for item in args.keys():
    source = "default"
    caster = casters[type(item)]
    env_var = f"{prefix}{item}".upper()
    if env_val :=  os.environ.get(env_var, None):
        env_val = caster(env_val) 
        args[item] = env_val
        source = env_var
    logger.debug(f"{item} set from {source}:value={args[item]}")


#########################
#
# make the model
#
#########################
@time_me    
def main():
    
    # Get more or less raw information from  underlying sources.
    # Create symbolic offsets to the tuple/lists 
    t0 = time.time()
    admin_topics = get_admin_info2(args)
    admini_topic = 0
    admini_descrip = admini_topic + 1
    admini_public  = admini_descrip + 1
    topic_descriptions  = { t[ admini_topic]: t[admini_descrip]  for t in admin_topics }
    
    archive_info = get_archive_info(args)
    # symbolic offsets within a list  
    archi_topic   = 0
    archi_group   = archi_topic + 1
    archi_time    = archi_group + 1
    archi_isoday  = archi_time  + 1

    all_public_topics = [i for i in admin_topics if i[admini_public] ]
    all_private_topics = [i for i in admin_topics  if not i[admini_public] ]
    
    info = {}
    
    #  The nature of the view means we need to organize topics by a list of                                                        
    #  Per-active-group information                                                                                                       

    # filter off times later than cutoff time, add human readable iso date
    cutoff_time = time.time() - 3600*24*args['days_recent']
    archive_info  = [ list(a) for a in archive_info if a[archi_time]/1000 > cutoff_time]
    for a in archive_info:
        isoday = datetime.date.fromtimestamp(a[archi_time]/1000).isoformat()
        a.append(isoday)

    # get a list of groups,
    groups = {item[archi_group] for item in archive_info}
    groups = sorted([g for g in groups])

    # build some summary stats 
    info['summary'] = {'n_public_topics'  : len(all_public_topics),
                       'n_private_topics'  : len(all_private_topics),
                       'active_threshold_days' : args['days_recent'],
                       'total_active_topics' : len(archive_info)
                       }

    # Build the model, group by group.
    gdata = []
    for g in groups :
        g_info = {}
        g_info['group_name'] = g
        public_topics = [ai for ai  in archive_info if a[archi_group] == g]
        g_info['public_topics'] = []
        for ai in archive_info:
            if ai[archi_group] != g : continue
            topic = ai[archi_topic]
            t_dict = {'topic' : topic,
                      'description' : topic_descriptions[topic],
                      'latest': ai[archi_isoday]
                      }
            g_info['public_topics'].append(t_dict)
        g_info['n_public'] = len(g_info['public_topics'])
        gdata.append(g_info)
    info['groups'] = gdata
    #import pprint
    #pprint.pp(info, indent=4)
    return info

def pretty():
    info = main()
    import pprint                                                                                                                                                                                            
    pprint.pp(info, indent=4)   
##################################################
#
# get most recent information  from archive
#   Create a ssh tunnel to support development fromoutside AWS.
#   Withing AWS connect directly.
#
##################################################

@time_me
def get_archive_info(args):
    items = []
    messages = apps.get_model(app_label='hopskotch_auth', model_name='RecentMessages')
    all_topics = messages.objects.using('archive').all()
    print ('***************' , all_topics, dir(all_topics))
    for topic in all_topics:
        print ("XXXX")
        print ('****', type(topic.topic), type(topic.timestamp))
        item = [topic.topic, topic.topic.split('.',1)[0], topic.timestamp]
        print (item)
        items.append(item)
    return items

@time_me
def get_archive_infox(args):

    """
    Access arcbive  db via tunnel or directly

    - Tunnel path for development
    - Direct path for deployment
    """
    db_info = get_rds_db(args['archive_db_instance'])
    """
    db_info = {
        'DBName' : os.getenv('ARCHIVE_DB_DBNAME'),
        'MasterUsername':  os.getenv('ARCHIVE_DB_USERNAME')
        }
    """
    if args['remote_tunnel']:
        logger.info("about to use tunnel")
        return archive_query(args,
                             '127.0.0.1',
                             args['tunnel_archive_local_port'],
                             db_info)
    else:
        logger.info("about to open directly")
        return archive_query(args,
                             db_info['Endpoint']['Address'],
                             db_info['Endpoint']['Port'],
                             db_info)

@time_me
def archive_query(args, host, port, db_info):
    "Obtain  information from the archive DB"
    print('begin' ,time.process_time())
    password  = get_secret(args,args['archive_db_secretname'] )
    #password  = os.getenv('ARCHIVE_DB_PASSWD')
    print('got secret' ,time.process_time())
    con = psycopg2.connect(
        dbname = db_info['DBName'],
        user = db_info['MasterUsername'],
        password = password,
        port = port,
        host = host
    )
    
    print('connected' ,time.process_time())
    cur = con.cursor()
    sql = '''
       SELECT
         distinct(topic) t,
         split_part(topic, '.',1) grp,
         max(timestamp) 
         FROM
           recent_messages
         WHERE  public = 't' 
          GROUP BY  topic
    ;
    '''
    sql = """
       SELECT
          topic AS t,
          split_part(topic, '.', 1) AS grp,
          max(timestamp) AS latest_time
       FROM
          recent_messages
       GROUP BY
          topic;
    """
    cur.execute(sql)
    print('queried' ,time.process_time())

    ret = [item for item in cur.fetchall()]
    logger.info(f"found{len(ret)} items in archive db")
    return ret

##################################################
#
# get most recent information  from archive
#   Create a ssh tunnel to support development fromoutside AWS.
#   Withing AWS connect directly.
#
##################################################
@time_me
def get_admin_info2(args):
    items = []
    KafkaTopic = apps.get_model(app_label='hopskotch_auth', model_name='KafkaTopic')
    all_topics = KafkaTopic.objects.all()
    for topic in all_topics:
        item = [topic.name, topic.description, topic.publicly_readable]
        items.append(item)
    return items





