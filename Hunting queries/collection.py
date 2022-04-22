import sys
from unittest import result
sys.path.append(".")
import pandas as pd
from cloudTrail import *

def hunting_S3_enumeration():
    """
    API returns a list of access points with bucket 
    """
    cloudTrail_events = get_events('EventName', 'ListAccessPoints')
    return cloudTrail_events

def hunting_specified_IP_action(eventDatasotre,ip):
    """
    investigate suspicious IP
    """
    queryStatement = start_query(
        "SELECT distinct eventTime, userIdentity.username, requestParameters, sourceIPAddress, userAgent from " 
        + str(eventDatasotre) +  " where sourceIPAddress = '" + str(ip) + "'"
    )
    queryId = queryStatement['QueryId']
    results = get_query_results(eventDatasotre, queryId)
    return results

def hunting_specific_userAgent_activity(eventDatasotre, userAgent):
    """
    Specific useragent activity 
    """
    queryStatement = start_query(
        "SELECT * from " + str(eventDatasotre) +  " where userAgent like '%" + userAgent + "%'"
    )
    queryId = queryStatement['QueryId']
    results = get_query_results(eventDatasotre, queryId)
    return results

def hunting_S3_bucket_exfiltration(eventDatasotre,requestParameters):
    """
    reveled that the IP address invoked the suspicious command.
    """
    queryStatement = start_query(
        "SELECT distinct eventName, userIdentity.userName, requestParameters, sourceIpAddress, userAgent FROM " 
        + str(eventDatasotre) +  " WHERE requestParameters like '%" + requestParameters + "%'" 
    )
    queryId = queryStatement['QueryId']
    results = get_query_results(eventDatasotre, queryId)
    print(results)
    return results

def hunting_specific_API_activity(eventDatasotre,ip,requestParameters):
    """
    search for activities from the specified IP and S3
    """
    specifiedIPAction = hunting_specified_IP_action(eventDatasotre,ip)
    
    for i in specifiedIPAction["QueryResultRows"]:
        print(type(i))
    return specifiedIPAction

def test():
    pd.set_option('display.max_columns', None)
    eventDatasotre = 'f6f5758b-4d46-4b16-b6a2-0714cfc372ff'

    s3Enueration = hunting_S3_enumeration()
    df_s3Enueration = pd.DataFrame(s3Enueration["Events"])


    specifiedIPAction = hunting_specified_IP_action(eventDatasotre,'98.10.33.127')
    df_specifiedIPAction = pd.DataFrame(specifiedIPAction["QueryResultRows"])

    specificUserAgentActivity = hunting_specific_userAgent_activity(eventDatasotre,'Linux')
    df_specificUserAgentActivity = pd.DataFrame(specificUserAgentActivity["QueryResultRows"])

    # S3BucketExfiltration = hunting_S3_bucket_exfiltration(eventDatasotre,'GetObject')
    # df_S3BucketExfiltration = pd.DataFrame(S3BucketExfiltration["QueryResultRows"])

    # specificAPIActivity = hunting_specific_API_activity(eventDatasotre,'98.10.33.127','test-aws-bucket-2022')
    # df_specificAPIActivity = pd.DataFrame(specificAPIActivity["QueryResultRows"])

    # print(df_s3Enueration)
    # print(df_specifiedIPAction)
    print(df_specificUserAgentActivity)
    # print(df_S3BucketExfiltration)
    # print(df_specificAPIActivity)


test()