from __future__ import unicode_literals, print_function
from neo4j.v1 import GraphDatabase
import platform
import requests
import json
import os

driver = None
restapi = requests.session()

def init_driver(database, user, password):
    global driver
    uri = "bolt://%s:7687" % database
    driver = GraphDatabase.driver(uri, auth=(user, password))
    restapi.auth = (user, password)
    return driver

def detect_db_config():
    """
    Detect bloodhound config, which is stored in appData.
    OS dependent according to https://electronjs.org/docs/api/app#appgetpathname
    """
    system = platform.system()
    if system == 'Windows':
        try:
            directory = os.environ['APPDATA']
        except KeyError:
            return (None, None)
        config = os.path.join(directory, 'BloodHound', 'config.json')
        try:
            with open(config, 'r') as configfile:
                configdata = json.load(configfile)
        except IOError:
            return (None, None)

    if system == 'Linux':
        try:
            directory = os.environ['XDG_CONFIG_HOME']
        except KeyError:
            try:
                directory = os.path.join(os.environ['HOME'], '.config')
            except KeyError:
                return (None, None)
        config = os.path.join(directory, 'bloodhound', 'config.json')
        try:
            with open(config, 'r') as configfile:
                configdata = json.load(configfile)
        except IOError:
            return (None, None)

    if system == 'Darwin':
        try:
            directory = os.path.join(os.environ['HOME'], 'Library', 'Application Support')
        except KeyError:
            return (None, None)
        config = os.path.join(directory, 'bloodhound', 'config.json')
        try:
            with open(config, 'r') as configfile:
                configdata = json.load(configfile)
        except IOError:
            return (None, None)

    # If we are still here, we apparently found the config :)
    try:
        username = configdata['databaseInfo']['user']
    except KeyError:
        username = 'neo4j'
    try:
        password = configdata['databaseInfo']['password']
    except KeyError:
        password = None
    return username, password

def close_driver():
    global driver
    driver.close()

preparequeries = [
    "MATCH (n)-[r:MemberOf]->(m:Group) SET r.aclpwncost = 0",
    "MATCH (n)-[r:AddMember|GenericAll|GenericWrite|AllExtendedRights]->(m:Group) SET r.aclpwncost = 1",
    "MATCH (n)-[r:WriteOwner]->(m:Group) SET r.aclpwncost = 3",
    "MATCH (n)-[r:WriteDacl|Owns]->(m:Group) SET r.aclpwncost = 2",
    # These privileges on user objects are not wanted since they work only when resetting passwords
    "MATCH (n)-[r:WriteDacl|Owns|WriteOwner|GenericAll|GenericWrite|ForceChangePassword|AllExtendedRights]->(m:User) SET r.aclpwncost = 200",
    "MATCH (n)-[r:WriteDacl]->(m:Domain) SET r.aclpwncost = 1",
    "MATCH (n)-[r:DCSync|GetChangesAll|AllExtendedRights]->(m:Domain) SET r.aclpwncost = 0",
]

def preparedb():
    global driver
    with driver.session() as session:
        with session.begin_transaction() as tx:
            for query in preparequeries:
                tx.run(query)