"""
Draw data from
- Scmma-admin  (topics, groups, topic descripton)
- Archive "how recent", public/private

Combine and arrange into a model for a web page.
"""

import logging
import datetime
import os
import time
from functools import wraps
from django.apps import apps

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)
log_format = "[%(asctime)s] %(name)s %(levelname)s %(message)s"
formatter = logging.Formatter(log_format, datefmt="%d/%B/%Y %H:%M:%S,%3d")
stream_handler.setFormatter(formatter)


DAYS_RECENT = os.getenv("DAYS_RECENT",90) 


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


#########################
#
# make the model
#
#########################
@time_me
def main():

    # Get more or less raw information from  underlying sources.
    # Create symbolic offsets to the tuple/lists
    admin_topics = get_admin_info()
    admini_topic = 0
    admini_descrip = admini_topic + 1
    admini_public = admini_descrip + 1
    topic_descriptions = {t[admini_topic]: t[admini_descrip] for t in admin_topics}

    archive_info = get_archive_info()
    # symbolic offsets within a list
    archi_topic = 0
    archi_group = archi_topic + 1
    archi_time = archi_group + 1
    archi_isoday = archi_time + 1

    all_public_topics = [i for i in admin_topics if i[admini_public]]
    all_private_topics = [i for i in admin_topics if not i[admini_public]]

    info = {}

    #  The nature of the view means we need to organize topics by a list of
    #  Per-active-group information

    # filter off times later than cutoff time, add human readable iso date
    cutoff_time = time.time() - 3600 * 24 * DAYS_RECENT
    archive_info = [list(a) for a in archive_info if a[archi_time] / 1000 > cutoff_time]
    for a in archive_info:
        isoday = datetime.date.fromtimestamp(a[archi_time] / 1000).isoformat()
        a.append(isoday)

    # get a list of groups,
    groups = {item[archi_group] for item in archive_info}
    groups = sorted([g for g in groups])

    # build some summary stats
    info["summary"] = {
        "n_public_topics": len(all_public_topics),
        "n_private_topics": len(all_private_topics),
        "active_threshold_days": DAYS_RECENT,
        "total_active_topics": len(archive_info),
    }

    # Build the model, group by group.
    gdata = []
    for g in groups:
        g_info = {}
        g_info["group_name"] = g
        g_info["public_topics"] = []
        for ai in archive_info:
            if ai[archi_group] != g:
                continue
            topic = ai[archi_topic]
            t_dict = {
                "topic": topic,
                "description": topic_descriptions[topic],
                "latest": ai[archi_isoday],
            }
            g_info["public_topics"].append(t_dict)
        g_info["n_public"] = len(g_info["public_topics"])
        gdata.append(g_info)
    info["groups"] = gdata
    return info

@time_me
def get_archive_info():
    items = []
    messages = apps.get_model(app_label="hopskotch_auth", model_name="RecentMessages")
    all_topics = messages.objects.using("archive").all()
    for topic in all_topics:
        item = [topic.topic, topic.topic.split(".", 1)[0], topic.timestamp]
        items.append(item)
    return items

@time_me
def get_admin_info():
    items = []
    KafkaTopic = apps.get_model(app_label="hopskotch_auth", model_name="KafkaTopic")
    all_topics = KafkaTopic.objects.all()
    for topic in all_topics:
        item = [topic.name, topic.description, topic.publicly_readable]
        items.append(item)
    return items
