import pandas as pd
from flask import Blueprint, render_template, request, flash
from cloudTrail import *
from collection import *
from persistence import *
import json

views = Blueprint('views', __name__)
pd.set_option('display.max_columns', None)


@views.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        attributesKey = request.form.get('attributesKey')
        attributesValue = request.form.get('attributesValue')

        if len(attributesKey) == 0:
            flash('Please enter a attributes key!', category='error')
        elif attributesKey != 'EventId' and attributesKey != 'EventName' and attributesKey != 'ReadOnly' and \
                attributesKey != 'Username' and attributesKey != 'ResourceType' and attributesKey != 'ResourceName' and \
                attributesKey != 'EventSource' and attributesKey != 'AccessKeyId':
            flash('Please enter a valid attributes key! For example: EventId, EventName, ReadOnly, Username, '
                  'ResourceType, ResourceName, EventSource, AccessKeyId',
                  category='error')
        elif len(attributesValue) == 0:
            flash('Please enter a valid attributes value! ', category='error')
        else:
            cloudTrail_events = get_events(attributesKey, attributesValue)
            events = cloudTrail_events['Events']
            df_events = pd.DataFrame(events)
            flash('Successful!', category='success')
            return render_template("home.html", boolean=True, tables=[df_events.to_html(classes='events')])
    return render_template("home.html", boolean=False)


@views.route('/collection', methods=['GET', 'POST'])
def collection():
    if request.method == 'POST':
        eventDatasotre = 'f6f5758b-4d46-4b16-b6a2-0714cfc372ff'

        if request.form['action'] == 's3Enumeration':
            s3Enueration = hunting_S3_enumeration()
            df_s3Enueration = pd.DataFrame(s3Enueration["Events"])
            data = df_s3Enueration['CloudTrailEvent']

            # convert json string to dataframe
            df_s3Enueration['Events'] = data.map(json.loads)
            df = pd.concat([pd.json_normalize(df_s3Enueration['Events'])], axis=1)

            d_new = {'eventTime': df["eventTime"], 'eventName': df["eventName"], 'sourceIPAddress': df["sourceIPAddress"],
                     'userName': df["userIdentity.userName"], 'bucket': df["requestParameters.bucket"],
                     'Host': df["requestParameters.Host"], 'maxResults': df["requestParameters.maxResults"],
                     'userAgent': df["userAgent"]}
            df_new = pd.DataFrame(data=d_new)
            df_new_distinct = df_new.groupby(['eventTime', 'eventName', 'sourceIPAddress', 'userName', 'bucket', 'Host',
                                     'maxResults', 'userAgent']).size().reset_index(name='Freq')
            return render_template("collection.html", boolean=True, tables=[df_new_distinct.to_html()])

        elif request.form['action'] == 'specificIPAction':
            attributesValue = request.form.get('attributesValue')
            if len(attributesValue) == 0:
                flash('Please enter a IP address! ', category='error')
            else:
                specifiedIPAction = hunting_specified_IP_action(eventDatasotre, attributesValue)
                df_specifiedIPAction = pd.DataFrame(specifiedIPAction["QueryResultRows"])

                d_new = {'eventTime':df_specifiedIPAction[0],'userName': df_specifiedIPAction[1],
                         'requestParameters': df_specifiedIPAction[2], 'sourceIPAddress': df_specifiedIPAction[3],
                         'userAgent': df_specifiedIPAction[4]}
                df_new = pd.DataFrame(data=d_new)
                return render_template("collection.html", boolean=True, tables=[df_new.to_html()])

        elif request.form['action'] == 'specificUserAgentActivity':
            attributesValue = request.form.get('attributesValue')
            print(attributesValue)
            if len(attributesValue) == 0:
                flash('Please enter a userAgent Activity! ', category='error')
            else:
                specificUserAgentActivity = hunting_specific_userAgent_activity(eventDatasotre, attributesValue)
                df_specificUserAgentActivity = pd.DataFrame(specificUserAgentActivity["QueryResultRows"])
                d_new = {'eventTime': df_specificUserAgentActivity[0], 'userName': df_specificUserAgentActivity[1],
                         'requestParameters': df_specificUserAgentActivity[2], 'sourceIPAddress': df_specificUserAgentActivity[3],
                         'userAgent': df_specificUserAgentActivity[4]}
                df_new = pd.DataFrame(data=d_new)
                return render_template("collection.html", boolean=True, tables=[df_new.to_html()])

    return render_template("collection.html")


@views.route('/persistence', methods=['GET', 'POST'])
def persistence():
    if request.method == 'POST':
        eventDatasotre = 'f6f5758b-4d46-4b16-b6a2-0714cfc372ff'
        if request.form['action'] == 'accessKeyCreation':
            accessKey = hunting_access_key_creation(eventDatasotre)
            df_accessKey = pd.DataFrame(accessKey["QueryResultRows"])
            return render_template("persistence.html", boolean=True, tables=[df_accessKey.to_html()])

    return render_template("persistence.html")

