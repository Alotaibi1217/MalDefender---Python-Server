import fleep
from onesignal_sdk.client import Client
import werkzeug
from flask import Flask, request
from flask_restful import Api, Resource, reqparse
import os
import pandas as pd
import pickle
import shlex
import threading
import subprocess

Final_Path = "final"
example_data = " Your File Has Been Uploaded To The Server "
REST_API_KEY = "MmNmYTUwYzYtY2MwZS00NjM5LWE5MWMtZDhmMmI5YjJjMGEz"
APP_ID = "c6e12511-5f40-4587-a512-628bf5e75f77"
USER_AUTH_KEY = "YzJlMmY2ZmEtNTNkNy00NWNjLThlMDgtMmE3ZjZlODMyZmU5"
Result = "test"
max_label = "test"

y = ['Subflow Fwd Pkts',
     'Subflow Bwd Pkts',
     'Fwd Seg Size Avg',
     'Fwd URG Flags',
     'Bwd URG Flags',
     'URG Flag Cnt',
     'CWE Flag Count',
     'ECE Flag Cnt',
     'Fwd Byts/b Avg',
     'Fwd Pkts/b Avg',
     'Fwd Blk Rate Avg',
     'Bwd Byts/b Avg',
     'Bwd Pkts/b Avg',
     'Bwd Blk Rate Avg',
     'Fwd Seg Size Min',
     'PSH Flag Cnt', 'Init Fwd Win Byts', 'Fwd PSH Flags']

Flow_Iden = ['Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Flow ID', 'Timestamp', 'Protocol']
pcap_sign = "b'\\xd4\\xc3\\xb2\\xa1\\x02\\x00\\x04\\x00\'"

app = Flask(__name__)
api = Api(app)


def PCAP_to_CSV(path2):
    path = path2
    command_path = "cd C:/Users/alota/Downloads/cicflowmeter-4/CICFlowMeter-4.0/bin &&"
    tool = "cfm.bat"
    des = "C:/Users/alota/Desktop/Project"
    command = "%s %s %s %s " % (command_path, tool, path, des)
    os.system(command)


def Full_Path(file2):
    dir = "C:/Users/alota/Desktop/Project/"
    file = file2
    print(file)
    full_path = os.path.join(dir, file)
    full_path = full_path + "_Flow.csv"
    return full_path


def Full_Path_PCAP(file2):
    dir = "C:/Users/alota/Desktop/Project/"
    file = file2
    print(file)
    full_path = os.path.join(dir, file)
    return full_path


def Predict(array1):
    count_labels = {'MALWARE': 0, 'BENGIN': 0}
    for i in range(0, len(array1)):
        if (array1[i] == 0):
            count_labels['BENGIN'] = count_labels['BENGIN'] + 1
        if (array1[i] == 1):
            count_labels['MALWARE'] = count_labels['MALWARE'] + 1
    malware_percetage = (count_labels['MALWARE'] / (count_labels['BENGIN'] + count_labels['MALWARE']))
    print(count_labels['MALWARE'])
    print(count_labels['BENGIN'])
    print(malware_percetage)
    if (malware_percetage > 0.06 and malware_percetage <= 0.1):
        max_label = "Not Sure"
    elif (malware_percetage >= 0.1):
        max_label = "Malware"
    else:
        max_label = "Benign"
    print(max_label)
    return max_label


def Send_Notification(ID2, label):
    client = Client(app_id=APP_ID, rest_api_key=REST_API_KEY, user_auth_key=USER_AUTH_KEY)
    if label != "invalid":
        Result = Predict(label)
    else:
        Result = "Invalid File Type"
    notification_body = {
        'contents': {'en': Result},
        'include_player_ids': [ID2],
    }
    response = client.send_notification(notification_body)
    print(response.body)


def do_all(file3, ID3):

    path = "C:/Users/alota/Desktop/Project/" + file3.filename
    PCAP_to_CSV(path)
    full_path = Full_Path(file3.filename)

    datax = pd.read_csv(full_path, low_memory=False)
    datax = datax.drop(y, axis=1)

    s1 = datax.loc[datax['Src IP'] == '0.0.0.0'].index
    s2 = datax.loc[datax['Src IP'] == '8.8.8.8'].index
    s3 = datax.loc[datax['Src IP'] == '8.8.4.4'].index
    datax = datax.drop(s1)
    datax = datax.drop(s2)
    datax = datax.drop(s3)

    datax = datax.drop(Flow_Iden, axis=1)
    datax = datax.dropna()
    datax = datax.drop('Label', axis=1)

    with open('model.pkl', 'rb') as f:
        clf2 = pickle.load(f)

    labels_pred = clf2.predict(datax)
    Send_Notification(ID3, labels_pred)


def signture(file4):
    filename = Full_Path_PCAP(file4.filename)
    with open(filename, 'rb') as fd:
        file_head = fd.read(8)
    return file_head


class PCAP(Resource):

    def __init__(self):
        self.parser = reqparse.RequestParser()

    def post(self):
        self.parser.add_argument("file", type=werkzeug.datastructures.FileStorage, location='files')
        ID = request.form.get("ID")
        print("this is the ID %s" % ID)
        args = self.parser.parse_args()
        file = args.get("file")
        file.save(os.path.join("C:/Users/alota/Desktop/Project", file.filename))

        sign = signture(file)
        if str(sign) == str(pcap_sign):
            threading.Thread(target=do_all(file, ID)).start()
        else:
            os.remove(Full_Path_PCAP(file.filename))
            Send_Notification(ID, "invalid")
        return example_data, 201


api.add_resource(PCAP, '/files')

if __name__ == '__main__':
    app.run(port=8080, host="192.168.1.14")
