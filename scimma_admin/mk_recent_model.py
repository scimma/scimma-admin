#!/usr/bin/env python3
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

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)
log_format='[%(asctime)s] %(name)s %(levelname)s %(message)s'
formatter = logging.Formatter(log_format, datefmt='%d/%B/%Y %H:%M:%S,%3d')
stream_handler.setFormatter(formatter)


print ('1****')
from django.apps import apps
#User = apps.get_model(app_label='auth', model_name='')
#print(User)
#<class 'django.contrib.auth.models.User'>

"""
print ('2****')
model = apps.get_model(app_label='hopskotch_auth', model_name='CredentialKafkaPermission')
print ('3****')
model = apps.get_model(app_label='hopskotch_auth', model_name='KafkaTopic')
print ('4****')
pprint.pp(dir(model), indent = 4)
print ('5****')
resp = model.objects.all()
print ('6****')
print(resp)
exit()
#<class 'django.contrib.auth.models.User'>
#<clases 'hopskotch_auth.models.GroupKafkaPermission'>
#<class 'hopskotch_auth.models.CredentialKafkaPermission'>
print ('7****')
mm = django.apps.apps.get_models()
print ('8****')
pprint.pp(mm, indent=4)
print ('9****')
"""
KafkaTopic = apps.get_model(app_label='hopskotch_auth', model_name='KafkaTopic')
pprint.pp (KafkaTopic.__dict__)
print ('10****')
pprint.pp (KafkaTopic.objects.__dict__)
print ('11****')
all_topics = KafkaTopic.objects.all()
print ('12****')
print (all_topics[0].__dict__)
print(13)
##################################################
#
# Utilities
#
##################################################

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


def get_rds_db(db_instance_id):
    logger.info( f"1*********")
#    rds = boto3.client("rds", region_name="us-west-2")
    rds = boto3.client("rds")
    logger.info( f"2*********")
    resp = rds.describe_db_instances(Filters=[
        {"Name": "db-instance-id", "Values": [db_instance_id]},
    ])
    logger.info( f"3*********")
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
    args['tunnel_admin_local_port'] = os.getenv('ADMIN_LOCAL_PORT')
    args['tunnel_archive_local_port'] = os.getenv('ARCHIVE_LOCAL_PORT')
    args['tunnel_ssh_username'] = os.getenv('REMOTE_USER')
    args['tunnel_ssh_pkey'] = '/Users/donaldp/.ssh/id_rsa'
    args['tunnel_ssh_archive_host'] =  os.getenv('ARCHIVE_HOST')
    args['tunnel_ssh_admin_host'] = os.getenv('ADMIN_HOST')

# Archive connect info #
args['archive_db_instance'] = os.getenv('ARCHIVE_DB_INSTANCE') 
args['archive_db_secretname'] = os.getenv('ARCHIVE_DB_SECRET_NAME')

# scimma-admin connect info
args['admin_db_instance'] = os.getenv('ADMIN_DB_INSTANCE') 
args['admin_db_secretname'] = os.getenv('ADMIN_DB_SECRET_NAME')


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
    logger.info(f"{item} set from {source}:value={args[item]}")


#########################
#
# make the model
#
#########################
    
def main():
    
    # Get more or less raw information from  underlying sources.
    # Create symbolic offsets to the tuple/lists 
    t0 = time.time()
    admin_topics = get_admin_info2(args)
    admini_topic = 0
    admini_descrip = admini_topic + 1
    admini_public  = admini_descrip + 1
    topic_descriptions  = { t[ admini_topic]: t[admini_descrip]  for t in admin_topics }
    logger.info( f"get admin info: {time.time()-t0}")
    
    archive_info = get_archive_info(args)
    # symbolic offsets within a list  
    archi_topic   = 0
    archi_group   = archi_topic + 1
    archi_time    = archi_group + 1
    archi_isoday  = archi_time  + 1
    logger.info( f"get archive_info: {time.time()-t0}")

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


def get_archive_info(args):

    """
    Access arcbive  db via tunnel or directly

    - Tunnel path for development
    - Direct path for deployment
    """
    logger.info( f"archive_info1 args['remote_tunnel' = {args['remote_tunnel']}")
    #db_info = get_rds_db(args['archive_db_instance'])
    db_info = {
        'DBName' : os.getenv('ARCHIVE_DB_DBNAME'),
        'MasterUsername':  os.getenv('ARCHIVE_DB_USERNAME')
        }
    logger.info( f"archive_info3 *************************")
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


def archive_query(args, host, port, db_info):
    "Obtain  information from the archive DB"
    #password  = get_secret(args,args['archive_db_secretname'] )
    password  = os.getenv('ARCHIVE_DB_PASSWD')
    t0 = time.time()
    con = psycopg2.connect(
        dbname = db_info['DBName'],
        user = db_info['MasterUsername'],
        password = password,
        port = port,
        host = host
    )
    
    cur = con.cursor()
    sql = '''
       SELECT
         distinct(topic) t,
         split_part(topic, '.',1) grp,
         max(timestamp) 
         FROM
           messages
         WHERE  public = 't' 
          GROUP BY  topic
    ;
    '''
    cur.execute(sql)
    ret = [item for item in cur.fetchall()]
    logger.info( f"get ARCHIVE info: {time.time()-t0}")        
    logger.info(f"found{len(ret)} items in archive db")
    return ret

##################################################
#
# get most recent information  from archive
#   Create a ssh tunnel to support development fromoutside AWS.
#   Withing AWS connect directly.
#
##################################################

def get_admin_info2(args):
    items = []
    KafkaTopic = apps.get_model(app_label='hopskotch_auth', model_name='KafkaTopic')
    all_topics = KafkaTopic.objects.all()
    for topic in all_topics:
        print (type(topic.name))
        item = [topic.name, topic.description, topic.publicly_readable]
        print(item)
        items.append(item)
    return items
    
def get_admin_info2k(args):
    """
    Access scimma-admin db via tunnel or directly

    - Tunnel path for development
    - Direct path for deployment
    """
    db_info = get_rds_db(args['admin_db_instance'])
    if args['remote_tunnel']:
        logger.info("about to open ssh tunnel")
        return admin_query(
            args,
            '127.0.0.1',
            args['tunnel_admin_local_port'],
            db_info)
    else:
        return admin_query(
            args,
            db_info['Endpoint']['Address'],
            db_info['Endpoint']['Port'],
            db_info
                    )

def admin_query(args, host, port, db_info):
    "obtain model info from acimma-admin database"
    
    password  = get_secret(args,args['admin_db_secretname'] )
    con = psycopg2.connect(
        dbname = db_info['DBName'],
        user = db_info['MasterUsername'],
        password = password,
        port = port,
        host = host
    )
    breakpoint()
    model = hopskotch_auth.models.CredentialKafkaPermission()
    t0 = time.time()
    cur = con.cursor()
    sql = '''select name, description, publicly_readable  from hopskotch_auth_kafkatopic; '''
    cur.execute(sql)
    ret = [item for item in cur.fetchall()]
    logger.info( f"get admin SELECT) info: {time.time()-t0}")
    logger.info(f"found{len(ret)} items in scimma-admin db")
    return ret

if __name__ == "__main__":
    pretty()




