import datetime
import collections
from multiprocessing.connection import wait
import boto3
import time

client = boto3.client('cloudtrail')
paginator = client.get_paginator('lookup_events')

startingToken = None

def get_events_summaries(events):
    """ 
    Summarizes CloudTrail events list by reducing into counters of occurences for each event, resource name, and resource type in list.
    Args:
        events (dict): Dictionary containing list of CloudTrail events to be summarized.
    Returns:
        (list, list, list)
        Lists containing name:count tuples of most common occurences of events, resource names, and resource types in events list.
    """
    event_name_counter = collections.Counter()
    resource_name_counter = collections.Counter()
    resource_type_counter = collections.Counter()
    for event in events['Events']:
        resources = event.get("Resources")
        event_name_counter.update([event.get('EventName')])
        if resources is not None:
            resource_name_counter.update([resource.get("ResourceName") for resource in resources])
            resource_type_counter.update([resource.get("ResourceType") for resource in resources])
    return event_name_counter.most_common(10), resource_name_counter.most_common(10), resource_type_counter.most_common(10)

def get_events(attributeKey, attributeValue):
    """
    Looks up management events or CloudTrail Insights events that are captured by CloudTrail.
    Args:
        attributeKey (string): Specifies an attribute on which to filter the events returned
        attributeValue (string): Specifies a value for the specified AttributeKey
    Returns:
        (dict)
        Contains a response to a LookupEvents action
    """
    response = client.lookup_events (
        LookupAttributes=[
            {
                'AttributeKey': attributeKey,
                'AttributeValue': attributeValue
            }
        ],
    )
    return response

def start_query(query):
    """
    Starts a CloudTrail Lake query. 
    Args:
        QueryStatement (string): The SQL code of your query.
    Returns:
        dict
    """
    response = client.start_query(
        QueryStatement=query
    )
    return response

def describe_query(eventDataStore,quertId):
    """
    Returns metadata about a query, including query run time in milliseconds, number of events scanned and matched, and query status.
    Args:
        eventDataStore (string): The ARN (or the ID suffix of the ARN) of an event data store on which the specified query was run.
        quertId (string): The query ID.
    Returns: (dict)
    """
    response = client.describe_query(
        EventDataStore = eventDataStore,
        QueryId = quertId
    )
    return response

def get_query_results(eventDatasotre,queryId):
    """
    Gets event data results of a query. 
    Args:
        eventDatasotre (string): The ARN (or ID suffix of the ARN) of the event data store against which the query was run.
        queryId (string): The ID of the query for which you want to get results.
        nextToken (string): A token you can use to get the next page of query results.
        maxQueryResults (integer): The maximum number of query results to display on a single page.
    Returns:

    """    
    describeQuery = describe_query(eventDatasotre,queryId)
    while (describeQuery['QueryStatus'] in ['RUNNING','QUEUED']):
        print ('Waiting for query to complete ...')
        time.sleep(1)
        describeQuery = describe_query(eventDatasotre,queryId)
        response = client.get_query_results(EventDataStore=eventDatasotre, QueryId=queryId)
    return response

def test():
    """
    test all funtions
    """
    start = time.time()
    cloudTrail_events = get_events('ReadOnly','true')
    end = time.time()

    events_summaries = get_events_summaries(cloudTrail_events)
    queryStatement = start_query("SELECT eventTime, userIdentity.username, requestParameters, sourceIPAddress, userAgent from f6f5758b-4d46-4b16-b6a2-0714cfc372ff where eventName = 'ListAccessPoints'")
    queryId = queryStatement["QueryId"]
    describeQuery = describe_query('f6f5758b-4d46-4b16-b6a2-0714cfc372ff',queryId)
    getQueryResult = get_query_results('f6f5758b-4d46-4b16-b6a2-0714cfc372ff',queryId)

    print(cloudTrail_events)
    print(f"Runtime of the program is {end - start}")
    # print(events_summaries)
    # print(queryId)
    # print(describeQuery)
    # print(getQueryResult)

test()