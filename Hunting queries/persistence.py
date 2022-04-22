import sys
from unittest import result
sys.path.append(".")
import pandas as pd
from cloudTrail import *

def hunting_access_key_creation(eventDatasotre):
    """
    Filertering on CreateAccessKey and UserIdentityUserName reveals that the IAM specific user created access keys for other admin user.
    """
    queryStatement = start_query(
        "SELECT distinct eventTime, userIdentity.username, requestParameters, sourceIPAddress, userAgent from " 
        + str(eventDatasotre) +  " WHERE eventName in ('CreateAccessKey') AND userIdentity.userName != ''"
    )
    queryId = queryStatement['QueryId']
    results = get_query_results(eventDatasotre, queryId)
    return results

def hunting_aws_account_enumeration(eventDatasotre):
    """
    Filerting on ListAccessKeys, ListUsers, ListGroups, ListRolePolicies, revelaed that the enumeration commands were invoked on the IAM specific account.
    """
    queryStatement = start_query(
        "SELECT distinct eventTime, eventName, userIdentity.username, requestParameters, sourceIPAddress, userAgent from " 
        + str(eventDatasotre) +  " WHERE eventName in ('ListAccessKeys','ListUsers','ListGroups','ListRolePolicies','GetCallerIdentity')"
    )
    queryId = queryStatement['QueryId']
    results = get_query_results(eventDatasotre, queryId)
    return results

def hunting_suspicious_user_agents(eventDatasotre,command):
    """
    Filtering on the “UserAgent” reveals that the attack came from a command "Kali Linux OS" with the specific user.
    """
    queryStatement = start_query(
        "SELECT distinct eventTime, eventName, userIdentity.username, requestParameters, sourceIPAddress, userAgent from " 
        + str(eventDatasotre) +  " WHERE userAgent like '%" + command + "%'"
    )
    queryId = queryStatement['QueryId']
    results = get_query_results(eventDatasotre, queryId)
    return results

def hunting_created_roles():
    """
    Investigate created roles and who created them.
    """
    results = get_events('EventName', 'CreateRole')
    return results

def hunting_role_added_to_instance_profile(eventDatasotre):
    """
    Investigate role added to the instance profile
    """
    return

def hunting_specific_role(eventDatasotre):
    """
    """
    return


def hunting_source_IP_accessing_aws_services():
    """
    """
    return

def hunting_suspicious_API_activities():
    """
    """
    return

def hunting_action_taken_by_aws_admin_users():
    """
    """
    return

def hunting_all_activity_realted_new_IAM_user():
    """
    """
    return

def hunting_IAM_accessKey_group_creation():
    """
    """
    return

def test():
    pd.set_option('display.max_columns', None)
    eventDatasotre = 'f6f5758b-4d46-4b16-b6a2-0714cfc372ff'

    accessKey = hunting_access_key_creation(eventDatasotre)
    df_accessKey = pd.DataFrame(accessKey["QueryResultRows"])

    awsAccountEnumeration = hunting_aws_account_enumeration(eventDatasotre)
    df_awsAccountEnumeration = pd.DataFrame(awsAccountEnumeration["QueryResultRows"])

    suspiciousUserAgents = hunting_suspicious_user_agents(eventDatasotre, 'kali') 
    df_suspiciousUserAgents = pd.DataFrame(suspiciousUserAgents["QueryResultRows"])
    start = time.time()
    createdRoles = hunting_created_roles()
    df_createdRoles = pd.DataFrame(createdRoles['Events'])
    end = time.time()
    # roleAddedToInstanceProfile = hunting_role_added_to_instance_profile(eventDatasotre)
    # df_roleAddedToInstanceProfile = pd.DataFrame(roleAddedToInstanceProfile["QueryResultRows"])

    # specificRole = hunting_specific_role(eventDatasotre)
    # df_specificRole = pd.DataFrame(specificRole["QueryResultRows"])

    # print(df_accessKey)
    # print(df_awsAccountEnumeration)
    # print(df_suspiciousUserAgents)
    print(df_createdRoles)
    print(f"Runtime of the program is {end - start}")
    # print(df_roleAddedToInstanceProfile)
    # print(df_specificRole)

test()