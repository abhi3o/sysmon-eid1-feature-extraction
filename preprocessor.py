import json
import datetime
import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search


SELECTED_COLS = ['Channel', 'EventID', 'UtcTime', 'Hostname', 'Domain', 'AccountName', 'AccountType', 'LogonId', 'LogonGuid', 'Identifier', 'Company', 'Product', 'IntegrityLevel', 'ParentUser', 'ParentProcessId', 'ParentProcessGuid', 'ParentImage', 'ParentCommandLine', 'Description', 'User', 'ProcessId', 'ProcessGuid', 'Executable', 'CurrentDirectory', 'Image', 'CommandLine']


# Normalize JSON data in the dataframe and return a flattened version
def normalizejson(df):
    json_struct = json.loads(df.to_json(orient='records')) 
    return pd.json_normalize(json_struct)

# Read data from an Elasticsearch index and return as a Pandas DataFrame
def readfromelasticsearch(indexname):
    es = Elasticsearch("http://localhost:9200")
    searchcontext = Search(using=es, index=indexname, doc_type='doc')

    # Filter out only the process creation events, i.e. Sysmon EventID 1 events
    s = searchcontext.query('query_string', query='winlog.event_id:1')
    response = s.execute()
    if not response.success():
        retutn None

    df = pd.DataFrame((d.to_dict() for d in s.scan()))
    return normalizejson(df)

# Read data from a JSON file and return it as a Pandas DataFrame
def readfromjsonfile(filename):
    df = pd.read_json(filename, lines=True, orient="records")
    return normalizejson(df)
    
# Standardize the column names of the Sysmon EventID 1 events
def renamecols(df): 
    if 'winlog.event_data.UtcTime' in df.columns:
        df.rename(columns={'winlog.event_data.UtcTime': 'UtcTime'}, inplace=True)
    if 'winlog.computer_name' in df.columns:
        df.rename(columns={'winlog.computer_name': 'Hostname'}, inplace=True)
    if 'winlog.user.domain' in df.columns:
        df.rename(columns={'winlog.user.domain': 'Domain'}, inplace=True)
    if 'winlog.user.name' in df.columns:
        df.rename(columns={'winlog.user.name': 'AccountName'}, inplace=True)
    if 'winlog.user.type' in df.columns:
        df.rename(columns={'winlog.user.type': 'AccountType'}, inplace=True)
    if 'winlog.event_data.User' in df.columns:
        df.rename(columns={'winlog.event_data.User': 'User'}, inplace=True)
    if 'winlog.event_data.ParentProcessId' in df.columns:
        df.rename(columns={'winlog.event_data.ParentProcessId': 'ParentProcessId'}, inplace=True)
    if 'winlog.event_data.ParentImage' in df.columns:
        df.rename(columns={'winlog.event_data.ParentImage': 'ParentImage'}, inplace=True)
    if 'winlog.event_data.ParentCommandLine' in df.columns:
        df.rename(columns={'winlog.event_data.ParentCommandLine': 'ParentCommandLine'}, inplace=True)
    if 'winlog.event_data.ProcessId' in df.columns:
        df.rename(columns={'winlog.event_data.ProcessId': 'ProcessId'}, inplace=True)
    if 'winlog.event_data.Image' in df.columns:
        df.rename(columns={'winlog.event_data.Image': 'Image'}, inplace=True)
    if 'winlog.event_data.CommandLine' in df.columns:
        df.rename(columns={'winlog.event_data.CommandLine': 'CommandLine'}, inplace=True)
    if 'winlog.channel' in df.columns:
        df.rename(columns={'winlog.channel': 'Channel'}, inplace=True)
    if 'winlog.event_id' in df.columns:
        df.rename(columns={'winlog.event_id': 'EventID'}, inplace=True)  
    if 'winlog.event_data.OriginalFileName' in df.columns:
        df.rename(columns={'winlog.event_data.OriginalFileName': 'Executable'}, inplace=True)
    if 'winlog.event_data.ProcessGuid' in df.columns:
        df.rename(columns={'winlog.event_data.ProcessGuid': 'ProcessGuid'}, inplace=True)
    if 'winlog.event_data.IntegrityLevel' in df.columns:
        df.rename(columns={'winlog.event_data.IntegrityLevel': 'IntegrityLevel'}, inplace=True)
    if 'winlog.event_data.Product' in df.columns:
        df.rename(columns={'winlog.event_data.Product': 'Product'}, inplace=True)
    if 'winlog.event_data.LogonId' in df.columns:
        df.rename(columns={'winlog.event_data.LogonId': 'LogonId'}, inplace=True)
    if 'winlog.event_data.Description' in df.columns:
        df.rename(columns={'winlog.event_data.Description': 'Description'}, inplace=True)
    if 'winlog.event_data.LogonGuid' in df.columns:
        df.rename(columns={'winlog.event_data.LogonGuid': 'LogonGuid'}, inplace=True)
    if 'winlog.event_data.CurrentDirectory' in df.columns:
        df.rename(columns={'winlog.event_data.CurrentDirectory': 'CurrentDirectory'}, inplace=True)
    if 'winlog.event_data.ParentProcessGuid' in df.columns:
        df.rename(columns={'winlog.event_data.ParentProcessGuid': 'ParentProcessGuid'}, inplace=True)
    if 'winlog.event_data.ParentUser' in df.columns:
        df.rename(columns={'winlog.event_data.ParentUser': 'ParentUser'}, inplace=True)
    if 'winlog.event_data.Company' in df.columns:
        df.rename(columns={'winlog.event_data.Company': 'Company'}, inplace=True)
    if 'winlog.user.identifier' in df.columns:
        df.rename(columns={'winlog.user.identifier': 'Identifier'}, inplace=True)

    return df


if __name__ == '__main__':
    df = readfromelasticsearch("winlogbeat-2024.02.04")
    # df = readfromjsonfile("./winlogbeat-2024.02.04.ndjson")

    # Convert the UTC timestamp to Pandas datetime format
    df['winlog.event_data.UtcTime'] =  pd.to_datetime(df['winlog.event_data.UtcTime'], format='%Y-%m-%d %H:%M:%S.%f')

    df = renamecols(df)
    df = df[SELECTED_COLS]

    # Filter the events for a specific time range
    # df = df.loc[df['UtcTime'] < datetime.datetime(2024, 2, 4, 12, 12, 48, 0)]
    # df = df.loc[df['UtcTime'] > datetime.datetime(2024, 2, 4, 11, 58, 58, 0)]

    # print('[DEBUG] DataFrame Shape: 'df.shape)

    df.to_csv("./process-creation-events.csv", header=True, index=False)
