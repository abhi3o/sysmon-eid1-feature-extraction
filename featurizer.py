import math
import string
import re
import pandas as pd
import numpy as np

from constants import exp0, exp1, exp2, exp3, exp4, exp5, exp6, exp7, exp8, exp9, exp10, exp11, exp12, exp13, exp14, exp15, exp16, exp17, exp18, exp19, exp20, exp21, exp22, exp23, unfamiliarityscore

# One hot encoding to register an event's parent process as a feature
def onehotencoder(df):
    df['Parent'] = df['ParentImage'].apply(lambda x: re.search(exp23, str(x)).group().strip().lower())
    encoderDF = pd.get_dummies(df['Parent'])
    return encoderDF

# TF-IDF vectorize the CommandLine Arguments of an event to register the arguments' frequency as a feature
def wordtfidfvectorizer(df):
    v1 = TfidfVectorizer(analyzer='word', max_features=300)
    w1 = v1.fit_transform(df['CommandLineArguments'])
    x1 = pd.DataFrame(w1.toarray().transpose(), v1.get_feature_names_out())
    df2 = x1.transpose()
    return df2, v1

# Extraction of other features which would characterise an event as anomalous or benign
def featurize(df):
    featureMatrix = pd.DataFrame()
    
    df['Description'] = df['Description'].replace('-', np.nan)
    featureMatrix['hasNoDescription'] = df['Description'].isna()

    df['Child'] = df['Image'].apply(lambda x: re.search(exp23, str(x)).group().strip().lower())
    featureMatrix['isALOLBIN'] = df['Child'].apply(lambda x: True if x in exp0 else (False if x == '-' else False))

    df['Image'] = df['Image'].str.replace(exp9, 'programfiles', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp10, 'programfiles', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp11, 'winsysdir', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp12, 'winsysdir', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp13, 'winsysdir', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp14, 'winsysdir', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp15, 'temp', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp16, 'alluserprofile', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp17, 'temp', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp18, 'windir\\\\', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp19, 'userprofile', regex=True, case=False)
    df['Image'] = df['Image'].str.replace(exp20, 'drive\\\\', regex=True, case=False)
    featureMatrix['fromUntrustedLocation'] = ~ df['Image'].str.match(exp1)

    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp9, 'programfiles', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp10, 'programfiles', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp11, 'winsysdir', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp12, 'winsysdir', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp13, 'winsysdir', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp14, 'winsysdir', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp15, 'temp', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp16, 'alluserprofile', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp21, 'public', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp17, 'temp', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp18, 'windir\\\\', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp22, 'downloads', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp19, 'userprofile', regex=True, case=False)
    df['CurrentDirectory'] = df['CurrentDirectory'].str.replace(exp20, 'drive\\\\', regex=True, case=False)
    featureMatrix['untrustedCWD'] = df['CurrentDirectory'].apply(lambda x: bool(re.search(exp2, str(x))))

    featureMatrix['isElevated'] = df['User'].apply(lambda x: bool(re.search(exp3, str(x))))

    featureMatrix['isParentNotALOLBin'] = df['Parent'].apply(lambda x: False if x in exp0 else True)

    featureMatrix['containsAnIPv4'] = df['CommandLine'].apply(lambda x: bool(re.search(exp4, str(x))))

    featureMatrix['filenameMismatch'] = df['Executable'].str.lower() != df['Child']

    uniqueParents = set(df['Parent'])
    pairCounts = unfamiliarityscore(df, uniqueParents)
    df['ParentChild'] = list(zip(df['Parent'], df['Child']))
    featureMatrix['isUnfamiliar'] = df['ParentChild'].apply(lambda x: 1 - pairCounts[x])

    featureMatrix['isScript'] = df['CommandLine'].apply(lambda x: bool(re.search(exp5, str(x))))

    featureMatrix['hasProtocol'] = df['CommandLine'].apply(lambda x: bool(re.search(exp6, str(x))))

    featureMatrix['hasNetworkPath'] = df['CommandLine'].apply(lambda x: bool(re.search(exp7, str(x)))) | df['CommandLine'].apply(lambda x: bool(re.search(exp8, str(x))))

    featureMatrix['Anomalous'] = df['Anomalous']

    return featureMatrix

if __name__ == '__main__':
    df= pd.read_csv("./process-creation-events.csv")
    df['CommandLine'] = df['CommandLine'].apply(lambda x: str(x).lstrip('\\?.'))
    df['CommandLine'] = df['CommandLine'].apply(lambda x: str(x).replace('"', ''))
    df['CommandLineArguments'] = df['CommandLine'].apply(lambda x: re.findall('\s(.+)', x) or '')
    df['CommandLineArguments'] = df['CommandLineArguments'].apply(lambda x: ','.join(map(str, x)))
    
    df1 = onehotencoder(df)
    df2, wordTfidfVectorizer = wordtfidfvectorizer(df)
    df3 = featurize(df)
    
    trainFeatureMatrix = pd.concat([df1, df2, df3], axis=1)
