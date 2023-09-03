from sqlalchemy.orm import sessionmaker
import subprocess
import shutil
from sqlalchemy import inspect, Column, select, func, Text
from sqlalchemy.sql.sqltypes import String, Integer
from sqlalchemy import create_engine, text, Table, MetaData
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OrdinalEncoder, OneHotEncoder, MinMaxScaler, LabelEncoder, LabelBinarizer
from sklearn.compose import ColumnTransformer
from sklearn.compose import make_column_selector as selector
from sklearn.preprocessing import FunctionTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OrdinalEncoder, OneHotEncoder, MinMaxScaler, LabelEncoder
from sklearn.compose import ColumnTransformer
import psycopg2
import os
import csv
import os.path
import random
import numpy as np
np.seterr(invalid='ignore')
import pandas as pd
import tensorflow as tf
os.environ['CUDA_VISIBLE_DEVICES'] = "0"
os.environ['TF_CUDNN_USE_AUTOTUNE'] = '0'
from matplotlib import rc
rc('text', usetex=True)
import matplotlib
matplotlib.rcParams['text.usetex'] = True
import matplotlib.pyplot as plt
plt.rcParams['font.family'] = 'DeJavu Serif'
plt.rcParams['font.serif'] = ['Times New Roman']
from matplotlib.patches import Patch  # for custom legend - square patches
import seaborn as sns
import matplotlib as mpl
from matplotlib import rc
rc('text', usetex=True)
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.preprocessing import LabelBinarizer
label_encoder = LabelEncoder()
label_binarizer = LabelBinarizer()
multilabel_binarizer = MultiLabelBinarizer()

unsw_flow_columns = ["id", "srcip", "sport", "dstip", "dport", "proto", "state", "dur", # "flags", "stimepcap", "payload", 
               "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts", 
               "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "transdepth", "resbdylen", "sjit", "djit", "stime", "ltime", 
               "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat", "issmipsports", "ctstatettl", "ctflwhttpmthd", "isftplogin", 
               "ctftpcmd", "cssrvsrc", "ctsrvdst", "ctdstltm", "ctsrcltm", "ctsrcdportltm", "ctdstsportltm", "ctdstsrcltm", "attackcat", "label"
               ]

class DataManager:
    db_host = os.environ.get('DB_HOST') # Get database connection details from environment variables set in docker-compose.yaml
    db_port = os.environ.get('DB_PORT')
    db_name = os.environ.get('DB_NAME')
    db_user = 'postgres'
    db_pwd = os.environ.get('DB_PASSWORD')
    
    def __init__(self, protocol='tcp', class_type='binary'):
        self.protocol = protocol
        self.class_type = class_type

    def merge_unsw_nb15_csvs(self):
        print("Combining CSV files of the UNSW_NB15 dataset into one CSV file ...", flush=True)
        try:
            unsw_csv_directory = os.path.join(os.path.dirname(__file__), 'data/unsw_nb15_dataset')
            input_files = ['UNSW_NB15_1.csv', 'UNSW_NB15_2.csv', 'UNSW_NB15_3.csv', 'UNSW_NB15_4.csv']
            input_files = [os.path.join(unsw_csv_directory, filename) for filename in input_files]
            output_file = os.path.join(unsw_csv_directory, 'UNSW_NB15_ALL.csv')
            with open(output_file, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['srcip', 'sport', 'dstip', 'dport', 'proto', 'state', 'dur', 'sbytes', 'dbytes','sttl', 
                                'dttl', 'sloss', 'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 
                                'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'transdepth', 'resbdylen', 'sjit', 'djit', 'stime', 'ltime', 
                                'sintpkt', 'dintpkt', 'tcprtt', 'synack', 'ackdat', 'issmipsports', 'ctstatettl', 'ctflwhttpmthd', 'isftplogin', 'ctftpcmd', 
                                'cssrvsrc', 'ctsrvdst', 'ctdstltm', 'ctsrcltm', 'ctsrcdportltm', 'ctdstsportltm', 'ctdstsrcltm', 'attackcat', 'label']) 
                for input_file in input_files:
                    with open(input_file, 'r') as file:
                        reader = csv.reader(file)
                        header = next(reader)
                        for row in reader:
                            writer.writerow(row)
            print(f"Input files: {input_files} merged successfully to output file: {output_file}", flush=True)
        except Exception as e:
            raise e

    def update_attackcat_unsw_nb15_csv(self):
        print(f"Checking dataset inconsistencies has started ...", flush=True)
        unsw_csv_directory = os.path.join(os.path.dirname(__file__), 'data/unsw_nb15_dataset')
        try:
            print("Checking and fixing inconsistency naming of attack categories in the UNSW_NB15 dataset ...", flush=True)
            input_file = os.path.join(unsw_csv_directory, 'UNSW_NB15_ALL.csv')
            value_variations = {
                'Normal': ['', ' '],
                'Exploits': ['Exploits ', ' Exploits', ' Exploits ', 'Exploit', 'Exploit ', ' Exploit', ' Exploit '],
                'Shellcode': ['Shellcode ', ' Shellcode', ' Shellcode '],
                'Backdoor': ['Backdoor ', ' Backdoor', ' Backdoor ', 'Backdoors', 'Backdoors ', ' Backdoors', ' Backdoors '],
                'Fuzzers': ['Fuzzers ', ' Fuzzers', ' Fuzzers '],
                'Analysis': ['Analysis ', ' Analysis', ' Analysis '],
                'Reconnaissance': ['Reconnaissance ', ' Reconnaissance', ' Reconnaissance '],
                'Worms': ['Worms ', ' Worms', ' Worms '],
                'DoS': ['DoS ', ' DoS', ' DoS '],
                'Generic': ['Generic ', ' Generic', ' Generic ']}
            column_header = 'attackcat'
            with open(input_file, 'r') as file:
                reader = csv.reader(file)
                rows = list(reader)
                header = rows[0]
                column_index = header.index(column_header)
                instances_changed = 0
                instances_changed_dict = {}
                for row in rows[1:]:
                    cell_value = row[column_index]
                    for unique_value, variations in value_variations.items():
                        if cell_value in variations or cell_value.strip() in variations: # if cell_value.strip() in variations:
                            row[column_index] = unique_value
                            instances_changed += 1
                            if unique_value in instances_changed_dict:
                                instances_changed_dict[unique_value] += 1
                            else:
                                instances_changed_dict[unique_value] = 1
            with open(input_file, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerows(rows)
            print(f"Column values updated successfully. Total instances changed: {instances_changed}", flush=True)
            for unique_value, count in instances_changed_dict.items():
                print(f"{unique_value}: {count}", flush=True)
        except Exception as e:
            raise e

    def insert_unsw_csv_to_table(self):
        print(f"Inserting dataset CSV data values to database table has started ...", flush=True)
        engine = create_engine(f"postgresql+psycopg2://{self.db_user}:{self.db_pwd}@{self.db_host}:{self.db_port}/{self.db_name}")
        metadata = MetaData()
        metadata.bind = engine
        unsw_csv_directory = os.path.join(os.path.dirname(__file__), 'data/unsw_nb15_dataset')
        input_file = os.path.join(unsw_csv_directory, 'UNSW_NB15_ALL.csv')
        table = Table('unsw_nb15_dataset_csv', metadata,
                            Column('srcip', String), 
                            Column('sport', String),
                            Column('dstip', String), 
                            Column('dport', String), 
                            Column('proto', String), 
                            Column('state', String),
                            Column('dur', String), 
                            Column('sbytes', String), 
                            Column('dbytes', String), 
                            Column('sttl', String), 
                            Column('dttl', String), 
                            Column('sloss', String), 
                            Column('dloss', String), 
                            Column('service', String),
                            Column('sload', String), 
                            Column('dload', String), 
                            Column('spkts', String), 
                            Column('dpkts', String),
                            Column('swin', String), 
                            Column('dwin', String), 
                            Column('stcpb', String), 
                            Column('dtcpb', String),
                            Column('smeansz', String), 
                            Column('dmeansz', String), 
                            Column('transdepth', String), 
                            Column('resbdylen', String), 
                            Column('sjit', String), 
                            Column('djit', String), 
                            Column('stime', String), 
                            Column('ltime', String), 
                            Column('sintpkt', String), 
                            Column('dintpkt', String), 
                            Column('tcprtt', String),
                            Column('synack', String), 
                            Column('ackdat', String), 
                            Column('issmipsports', String), 
                            Column('ctstatettl', String),
                            Column('ctflwhttpmthd', String), 
                            Column('isftplogin', String), 
                            Column('ctftpcmd', String), 
                            Column('cssrvsrc', String),
                            Column('ctsrvdst', String), 
                            Column('ctdstltm', String), 
                            Column('ctsrcltm', String), 
                            Column('ctsrcdportltm', String),
                            Column('ctdstsportltm', String), 
                            Column('ctdstsrcltm', String), 
                            Column('attackcat', String), 
                            Column('label', String))
        print("Inserting UNSW_NB15 dataset CSV file (UNSW_NB15_ALL.csv) to a database table ...", flush=True)
        metadata.create_all(engine, checkfirst=True)
        with engine.begin() as connection:
            try:
                with open(input_file, 'r') as file:
                    reader = csv.reader(file)
                    header = next(reader)
                    for row in reader:
                        input_data = {column: value for column, value in zip(header, row)}
                        insert_stmt = table.insert().values(**input_data)
                        connection.execute(insert_stmt)
                os.remove(input_file) # Delete the CSV file
                print(f"CSV file {input_file} deleted successfully.", flush=True)
                connection.commit()
                print(f"UNSW_NB_15 dataset CSV values inserted to table 'unsw_nb15_dataset_csv' successfully.", flush=True)
            except Exception as e:
                raise e
            finally:
                if connection:
                    connection.close()
    
    def get_non_redundant_unsw_csv(self):
        print(f"UNSW-NB15 Dataset: Cleaning Redundant CSV data values from dataset started.", flush=True)
        engine = create_engine(f"postgresql+psycopg2://{self.db_user}:{self.db_pwd}@{self.db_host}:{self.db_port}/{self.db_name}")
        metadata = MetaData()
        metadata.bind = engine
        tbl_original = Table('unsw_nb15_dataset_csv', metadata,
                            Column('srcip', String), 
                            Column('sport', String),
                            Column('dstip', String), 
                            Column('dport', String), 
                            Column('proto', String), 
                            Column('state', String),
                            Column('dur', String), 
                            Column('sbytes', String), 
                            Column('dbytes', String), 
                            Column('sttl', String), 
                            Column('dttl', String), 
                            Column('sloss', String), 
                            Column('dloss', String), 
                            Column('service', String),
                            Column('sload', String), 
                            Column('dload', String), 
                            Column('spkts', String), 
                            Column('dpkts', String),
                            Column('swin', String), 
                            Column('dwin', String), 
                            Column('stcpb', String), 
                            Column('dtcpb', String),
                            Column('smeansz', String), 
                            Column('dmeansz', String), 
                            Column('transdepth', String), 
                            Column('resbdylen', String), 
                            Column('sjit', String), 
                            Column('djit', String), 
                            Column('stime', String), 
                            Column('ltime', String), 
                            Column('sintpkt', String), 
                            Column('dintpkt', String), 
                            Column('tcprtt', String),
                            Column('synack', String), 
                            Column('ackdat', String), 
                            Column('issmipsports', String), 
                            Column('ctstatettl', String),
                            Column('ctflwhttpmthd', String),
                            Column('isftplogin', String),
                            Column('ctftpcmd', String), 
                            Column('cssrvsrc', String),
                            Column('ctsrvdst', String), 
                            Column('ctdstltm', String), 
                            Column('ctsrcltm', String),
                            Column('ctsrcdportltm', String),
                            Column('ctdstsportltm', String),
                            Column('ctdstsrcltm', String),
                            Column('attackcat', String),
                            Column('label', String))
        with engine.begin() as connection:
            try:
                subquery = select(tbl_original).group_by(*tbl_original.c).having(func.count() > 1)
                redundant_rows = connection.execute(subquery).fetchall()
                num_redundancies = len(redundant_rows)
                for row in redundant_rows:
                        delete_stmt = tbl_original.delete().where(tbl_original.c == row)
                        connection.execute(delete_stmt)
                print(f"Number of redundant rows removed: {num_redundancies}", flush=True)
                inspector = inspect(engine)
                if inspector.has_table('unsw_nb15_dataset_csv'): # TODO: <pre>sqlalchemy.exc.ProgrammingError: (psycopg2.errors.DuplicateTable) relation &quot;unsw_nb15_csv_features_cleaned&quot; already exists</pre>
                    if inspector.has_table('unsw_nb15_csv_features_cleaned'):
                        drop_query = text("DROP TABLE IF EXISTS unsw_nb15_csv_features_cleaned")
                        connection.execute(drop_query)
                        print("Pre-existing Table 'unsw_nb15_csv_features_cleaned' dropped.")
                    sql_rename = text("ALTER TABLE IF EXISTS unsw_nb15_dataset_csv RENAME TO unsw_nb15_csv_features_cleaned")
                    connection.execute(sql_rename)
                    print("Table unsw_nb15_dataset_csv renamed to 'unsw_nb15_csv_features_cleaned' successfully.", flush=True)
                    print("Redundant data in UNSW_NB_15 dataset removed from Table 'unsw_nb15_dataset_csv'.", flush=True)
                    print("Non-redundant values of the dataset inserted to Table 'unsw_nb15_csv_features_cleaned'.", flush=True)
                else:
                    print(f"Table 'unsw_nb15_dataset_csv' does not exist.")
                connection.commit()
            except Exception as e:
                connection.rollback()
                raise e
            finally:
                if connection:
                    connection.close()
    
    def extract_data_from_unsw_pcaps(self, protocol):
        print(f"UNSW-NB15 Dataset: PCAP data extraction from dataset has started for protocol: {protocol}.", flush=True)
        try:
            if shutil.which('tshark') is None: # Check if 'tshark' is installed
                print("'tshark' is not installed or not found in the system's PATH.", flush=True)
                print("Please install 'tshark' before running this program.", flush=True)
                print("In Linux, 'apt-get install tshark' can be used to install tshark. Check documentation for your particular system.", flush=True)
                exit(1)
            root_directory = "data/unsw_nb15_dataset"
            required_files = {
                "feb_pcap": ['1.pcap', '2.pcap', '3.pcap', '4.pcap', '5.pcap', '6.pcap', '7.pcap', '8.pcap', '9.pcap', '10.pcap',
                                    '11.pcap', '12.pcap', '13.pcap', '14.pcap', '15.pcap', '16.pcap', '17.pcap', '18.pcap', '19.pcap', '20.pcap',
                                    '21.pcap', '22.pcap', '23.pcap', '24.pcap', '25.pcap', '26.pcap', '27.pcap'],
                "jan_pcap": ['1.pcap', '2.pcap', '3.pcap', '4.pcap', '5.pcap', '6.pcap', '7.pcap', '8.pcap', '9.pcap', '10.pcap',
                                    '11.pcap', '12.pcap', '13.pcap', '14.pcap', '15.pcap', '16.pcap', '17.pcap', '18.pcap', '19.pcap', '20.pcap',
                                    '21.pcap', '22.pcap', '23.pcap', '24.pcap', '25.pcap', '26.pcap', '27.pcap', '28.pcap', '29.pcap', '30.pcap',
                                    '31.pcap', '32.pcap', '33.pcap', '34.pcap', '35.pcap', '36.pcap', '37.pcap', '38.pcap', '39.pcap', '40.pcap',
                                    '41.pcap', '42.pcap', '43.pcap', '44.pcap', '45.pcap', '46.pcap', '47.pcap', '48.pcap', '49.pcap', '50.pcap', 
                                    '51.pcap', '52.pcap', '53.pcap']
            }
            required_files = {
                "feb_pcap": ['1.pcap', '2.pcap', '3.pcap', '4.pcap', '5.pcap', '6.pcap', '7.pcap', '8.pcap', '9.pcap', '10.pcap',
                                '11.pcap', '12.pcap', '13.pcap', '14.pcap', '15.pcap', '16.pcap', '17.pcap', '18.pcap', '19.pcap', '20.pcap',
                                '21.pcap', '22.pcap', '23.pcap', '24.pcap', '25.pcap', '26.pcap', '27.pcap'],
                "jan_pcap": ['1.pcap', '2.pcap', '3.pcap', '4.pcap', '5.pcap', '6.pcap', '7.pcap', '8.pcap', '9.pcap', '10.pcap',
                                '11.pcap', '12.pcap', '13.pcap', '14.pcap', '15.pcap', '16.pcap', '17.pcap', '18.pcap', '19.pcap', '20.pcap',
                                '21.pcap', '22.pcap', '23.pcap', '24.pcap', '25.pcap', '26.pcap', '27.pcap', '28.pcap', '29.pcap', '30.pcap',
                                '31.pcap', '32.pcap', '33.pcap', '34.pcap', '35.pcap', '36.pcap', '37.pcap', '38.pcap', '39.pcap', '40.pcap',
                                '41.pcap', '42.pcap', '43.pcap', '44.pcap', '45.pcap', '46.pcap', '47.pcap', '48.pcap', '49.pcap', '50.pcap', 
                                '51.pcap', '52.pcap', '53.pcap']
            }
            for subdir in required_files:
                if not os.path.isdir(os.path.join(root_directory, subdir)):
                    print(f"Sub-directory not found: {subdir}", flush=True)
                    print(f"Please create the sub-directory '{subdir}' and place the required file(s) inside it.", flush=True)
                    exit()
                subdir_files = required_files[subdir]
                for file_name in subdir_files:
                    input_file = os.path.join(root_directory, subdir, file_name)
                    output_file = os.path.join(root_directory, subdir, str(protocol) + "_" + str(subdir) + "_features.csv")
                    if not os.path.isfile(input_file):
                        print(f"Missing file in {subdir}: {file_name}", flush=True)
                        print(f"Please place the file '{file_name}' in the '{subdir}' sub-directory.", flush=True)
                        exit()
                    try:
                        if protocol == 'tcp':
                            command = ['tshark', '-r', input_file, '-Y', 'tcp', '-T', 'fields', 
                                       '-e', 'frame.time_epoch', '-e', 'ip.src', '-E', 'occurrence=f', 
                                       '-e', 'tcp.srcport', '-e', 'ip.dst', '-E', 'occurrence=f', 
                                       '-e', 'tcp.dstport', '-e', 'tcp.payload',
                                    '-E', 'separator=|']
                        elif protocol == 'udp':
                            command = ['tshark', '-r', input_file, '-Y', 'udp', '-T', 'fields', 
                                       '-e', 'frame.time_epoch', '-e', 'ip.src', '-E', 'occurrence=f', 
                                       '-e', 'udp.srcport', '-e', 'ip.dst', '-E', 'occurrence=f', 
                                       '-e', 'udp.dstport', '-e', 'udp.payload',
                                    '-E', 'separator=|']
                        else:
                            print("Unknown protocol. Exiting ...")
                            exit()
                        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
                        with open(output_file, 'a') as file: # Caution: appending mode so program should be run only once as data would repeat.
                            for line in process.stdout:
                                file.write(line)
                                print(line, end='', flush=True)
                        process.wait()
                    except subprocess.CalledProcessError as e:
                        print("Error running tshark:", e)
                        return
            print(f"\n Payload extraction is complete. Contents are saved to '{output_file}'. ", flush=True)
        except Exception as e:
            raise e

    def insert_unsw_pcap_data_to_table(self, protocol='tcp'): 
        print(f"UNSW-NB15 Dataset: Inserting extracted PCAP data values to database table has started.", flush=True)
        root_directory = "data/unsw_nb15_dataset"
        required_files = {
            "feb_pcap": [str(protocol) + "_feb_pcap_features.csv"],
            "jan_pcap": [str(protocol) + "_jan_pcap_features.csv"]
        }
        engine = create_engine(f"postgresql+psycopg2://{self.db_user}:{self.db_pwd}@{self.db_host}:{self.db_port}/{self.db_name}")
        metadata = MetaData()
        metadata.bind = engine
        with engine.begin() as connection:
            try:
                for subdir in required_files:
                    if not os.path.isdir(os.path.join(root_directory, subdir)):
                        print(f"Sub-directory not found: {subdir}", flush=True)
                        print(f"Please create the sub-directory '{subdir}' and place the required file(s) inside it.", flush=True)
                        exit()
                    tbl_name = str(protocol) + "_" + str(subdir) + "_features"
                    tbl = Table(tbl_name, metadata, 
                                Column('stimepcap', String), 
                                Column('srcip', String),
                                Column('sport', String), 
                                Column('dstip', String), 
                                Column('dport', String), 
                                Column('payload', Text))
                    tbl.create(bind=engine, checkfirst=True)
                    subdir_files = required_files[subdir]
                    for file_name in subdir_files:
                        input_file = os.path.join(root_directory, subdir, file_name)
                        with open(input_file, 'r') as file:
                            reader = csv.reader(file, delimiter='|')
                            for row in reader:
                                input_data = {column: value for column, value in zip(tbl.columns, row)}
                                insert_stmt = tbl.insert().values(input_data)
                                connection.execute(insert_stmt)
                        if not os.path.isfile(input_file):
                            print(f"Missing file in {subdir}: {file_name}", flush=True)
                            print(f"Please place the file '{file_name}' in the '{subdir}' sub-directory.", flush=True)
                            exit()
                        os.remove(input_file)
                        print(f"CSV file {input_file} deleted successfully.", flush=True)
                connection.commit()
                print(f"UNSW-NB15 Dataset: PCAP data from the dataset successfully inserted to table '{tbl_name}'.", flush=True)
            except Exception as e:
                connection.rollback()
                raise e
            finally:
                if connection:
                    connection.close()
    
    def create_labeled_payloads_for_unsw(self, protocol='tcp'):
        print(f"UNSW-NB15 Dataset: Labeling process of dataset's PCAP data has started.", flush=True)
        engine = create_engine(f"postgresql+psycopg2://{self.db_user}:{self.db_pwd}@{self.db_host}:{self.db_port}/{self.db_name}")
        metadata = MetaData()
        metadata.bind = engine
        label_tbl_name = 'unsw_nb15_csv_features_cleaned'
        label_tbl = Table(label_tbl_name, metadata, 
                        Column('srcip', String),
                        Column('sport', String),
                        Column('dstip', String), 
                        Column('dport', String), 
                        Column('proto', String), 
                        Column('state', String),
                        Column('dur', String), 
                        Column('sbytes', String), 
                        Column('dbytes', String), 
                        Column('sttl', String), 
                        Column('dttl', String), 
                        Column('sloss', String), 
                        Column('dloss', String), 
                        Column('service', String),
                        Column('sload', String), 
                        Column('dload', String), 
                        Column('spkts', String), 
                        Column('dpkts', String),
                        Column('swin', String), 
                        Column('dwin', String), 
                        Column('stcpb', String), 
                        Column('dtcpb', String),
                        Column('smeansz', String), 
                        Column('dmeansz', String), 
                        Column('transdepth', String), 
                        Column('resbdylen', String), 
                        Column('sjit', String), 
                        Column('djit', String), 
                        Column('stime', String), 
                        Column('ltime', String), 
                        Column('sintpkt', String), 
                        Column('dintpkt', String), 
                        Column('tcprtt', String),
                        Column('synack', String), 
                        Column('ackdat', String), 
                        Column('issmipsports', String), 
                        Column('ctstatettl', String),
                        Column('ctflwhttpmthd', String), 
                        Column('isftplogin', String), 
                        Column('ctftpcmd', String), 
                        Column('cssrvsrc', String),
                        Column('ctsrvdst', String), 
                        Column('ctdstltm', String), 
                        Column('ctsrcltm', String), 
                        Column('ctsrcdportltm', String),
                        Column('ctdstsportltm', String), 
                        Column('ctdstsrcltm', String), 
                        Column('attackcat', String), 
                        Column('label', String))
        label_tbl.create(bind=engine, checkfirst=True)
        root_directory = "data/unsw_nb15_dataset"
        required_files = {
            "feb_pcap": [str(protocol) + "_pcap_features.csv"],
            "jan_pcap": [str(protocol) + "_pcap_features.csv"]
        }
        for subdir in required_files:
            if not os.path.isdir(os.path.join(root_directory, subdir)):
                print(f"Sub-directory not found: {subdir}", flush=True)
                print(f"Please create the sub-directory '{subdir}' and place the required file(s) inside it.", flush=True)
                exit()
            pcap_tbl_name = str(protocol) + "_" + str(subdir) + "_features"
            pcap_tbl = Table(pcap_tbl_name, metadata, 
                            Column('stimepcap', String), 
                            Column('srcip', String),
                            Column('sport', String),
                            Column('dstip', String),
                            Column('dport', String),
                            Column('payload', Text))
            pcap_tbl.create(bind=engine, checkfirst=True)
            output_tbl_name = str(protocol) + "_" + str(subdir) + "_labeled_payload"
            output_tbl = Table(output_tbl_name, metadata,
                            Column('stimepcap', String), 
                            Column('srcip', String),
                            Column('sport', String), 
                            Column('dstip', String), 
                            Column('dport', String), 
                            Column('payload', Text),
                            Column('proto', String), 
                            Column('state', String),
                            Column('dur', String), 
                            Column('sbytes', String), 
                            Column('dbytes', String), 
                            Column('sttl', String), 
                            Column('dttl', String), 
                            Column('sloss', String), 
                            Column('dloss', String), 
                            Column('service', String),
                            Column('sload', String), 
                            Column('dload', String), 
                            Column('spkts', String), 
                            Column('dpkts', String),
                            Column('swin', String), 
                            Column('dwin', String), 
                            Column('stcpb', String), 
                            Column('dtcpb', String),
                            Column('smeansz', String), 
                            Column('dmeansz', String), 
                            Column('transdepth', String), 
                            Column('resbdylen', String), 
                            Column('sjit', String), 
                            Column('djit', String), 
                            Column('stime', String), 
                            Column('ltime', String), 
                            Column('sintpkt', String), 
                            Column('dintpkt', String), 
                            Column('tcprtt', String),
                            Column('synack', String), 
                            Column('ackdat', String), 
                            Column('issmipsports', String), 
                            Column('ctstatettl', String),
                            Column('ctflwhttpmthd', String), 
                            Column('isftplogin', String), 
                            Column('ctftpcmd', String), 
                            Column('cssrvsrc', String),
                            Column('ctsrvdst', String), 
                            Column('ctdstltm', String), 
                            Column('ctsrcltm', String), 
                            Column('ctsrcdportltm', String),
                            Column('ctdstsportltm', String), 
                            Column('ctdstsrcltm', String), 
                            Column('attackcat', String), 
                            Column('label', String))
            output_tbl.create(bind=engine, checkfirst=True)
            condition = (
                    (func.split_part(pcap_tbl.c.stimepcap, '.', 1)  == label_tbl.c.stime) &
                    (pcap_tbl.c.srcip == label_tbl.c.srcip) & 
                    (pcap_tbl.c.sport == label_tbl.c.sport) & 
                    (pcap_tbl.c.dstip == label_tbl.c.dstip) & 
                    (pcap_tbl.c.dport == label_tbl.c.dport) & 
                    (label_tbl.c.proto == protocol)
                )
            select_stmnt = select(pcap_tbl.c.stimepcap, 
                        pcap_tbl.c.srcip, 
                        pcap_tbl.c.sport, 
                        pcap_tbl.c.dstip, 
                        pcap_tbl.c.dport, 
                        pcap_tbl.c.payload,
                        label_tbl.c.proto, 
                        label_tbl.c.state, 
                        label_tbl.c.dur, 
                        label_tbl.c.sbytes, 
                        label_tbl.c.dbytes, 
                        label_tbl.c.sttl,
                        label_tbl.c.dttl, 
                        label_tbl.c.sloss, 
                        label_tbl.c.dloss, 
                        label_tbl.c.service,
                        label_tbl.c.sload, 
                        label_tbl.c.dload, 
                        label_tbl.c.spkts, 
                        label_tbl.c.dpkts,
                        label_tbl.c.swin, 
                        label_tbl.c.dwin, 
                        label_tbl.c.stcpb, 
                        label_tbl.c.dtcpb,
                        label_tbl.c.smeansz, 
                        label_tbl.c.dmeansz, 
                        label_tbl.c.transdepth,
                        label_tbl.c.resbdylen, 
                        label_tbl.c.sjit, 
                        label_tbl.c.djit, 
                        label_tbl.c.stime,
                        label_tbl.c.ltime, 
                        label_tbl.c.sintpkt, 
                        label_tbl.c.dintpkt, 
                        label_tbl.c.tcprtt,
                        label_tbl.c.synack, 
                        label_tbl.c.ackdat, 
                        label_tbl.c.issmipsports, 
                        label_tbl.c.ctstatettl,
                        label_tbl.c.ctflwhttpmthd, 
                        label_tbl.c.isftplogin, 
                        label_tbl.c.ctftpcmd, 
                        label_tbl.c.cssrvsrc,
                        label_tbl.c.ctsrvdst, 
                        label_tbl.c.ctdstltm, 
                        label_tbl.c.ctsrcltm, 
                        label_tbl.c.ctsrcdportltm,
                        label_tbl.c.ctdstsportltm, 
                        label_tbl.c.ctdstsrcltm,
                        label_tbl.c.attackcat, 
                        label_tbl.c.label).where(condition)
            with engine.begin() as connection:
                try:
                    result = connection.execute(select_stmnt)
                    for row in result:
                        input_data = {column: value for column, value in zip(output_tbl.columns, row)}
                        insert_stmt = output_tbl.insert().values(input_data)
                        connection.execute(insert_stmt)
                    print(f"Labeled PCAP data values inserted successfully to table '{output_tbl_name}'.", flush=True)
                    inspector = inspect(engine)
                    if inspector.has_table(pcap_tbl_name):
                        sql_drop = text(f"DROP TABLE {pcap_tbl_name}")
                        connection.execute(sql_drop)
                        print(f"Table {pcap_tbl_name} dropped.")
                    else:
                        print(f"Table {pcap_tbl_name} does not exist.")
                    connection.commit()
                except Exception as e:
                    connection.rollback()
                    raise e
                finally:
                    if connection:
                        connection.close()

    def get_payload_data(self, df, num_bytes): ### TODO: Normalize payload entries
        X_list = df["payload"].to_list()
        X_tensor_list = []
        for element in X_list:
            numeric_tensor=tf.io.decode_raw(input_bytes=element, out_type=tf.int32, little_endian=False, fixed_length=num_bytes, name=None) # Convert raw bytes from input tensor into numeric tensors. Returns: A Tensor object storing the decoded bytes.
            X_tensor_list.append(numeric_tensor)
        X_train = np.array(X_tensor_list).astype(np.int32) # astype(np.float32) # astype(np.int32)
        scaler = StandardScaler() # Normalize the data using StandardScaler
        X_train_normalized = scaler.fit_transform(X_train)
        # print("X_train_normalized: \n", X_train_normalized)
        return X_train_normalized
    
    def get_unsw_flow_data(self, df):
        # Netflowv9:
            ##### The following 6 Netflow Features are to dropped from training to avoid bias in ML training. ###########
            # %IPV4_SRC_ADDR --> srcip
            # %L4_SRC_PORT --> sport
            # %IPV4_DST_ADDR --> dstip
            # %L4_DST_PORT --> dsport
            # %FLOW_START_MILLISECONDS --> stime
            # %FLOW_END_MILLISECONDS --> ltime
            # %PROTOCOL_MAP --> proto
            ##### The following 6 Netflow Features are to be considered in future work. ###########
            # %FLOW_DURATION_MILLISECONDS --> dur
            # %IN_BYTES --> dbytes
            # %IN_PKTS --> dpkts
            # %OUT_BYTES --> sbytes 
            # %OUT_PKTS --> spkts
            # %L7_PROTO_NAME --> service
            ##### The following 7 Netflow Features are to be considered in future work. ###########
            # %MIN_PKT_LNGTH %MAX_PKT_LNGTH --> smeansz, dmeansz
            # %TCP_FLAGS 
            # %MIN_TTL %MAX_TTL --> sttl, dttl
            # %TCP_WIN_MAX_IN %TCP_WIN_MAX_OUT 
        drop_cols = ["attackcat", "label", "srcip", "sport", "dstip", "dport", "proto", "stime", "ltime",
                        "sttl", "dttl", "sloss", "dloss", "sload", "dload",
                        "smeansz", "dmeansz", "transdepth", "resbdylen", "sjit", "djit",
                        "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat", "issmipsports", "ctstatettl",
                        "ctflwhttpmthd", "isftplogin", "ctftpcmd", "cssrvsrc", "ctsrvdst", "ctdstltm", "ctsrcltm", 
                        "ctsrcdportltm", "ctdstsportltm", "ctdstsrcltm"]
        # X_train_df = df.drop(columns=["attackcat","label", "srcip", "sport", "dstip", "dport", "proto"]) # ,"service" # , "stime", "ltime"])
        X_train_df = df.drop(columns=drop_cols)
        X_train_df.replace(['', ' ', '\n', '\t'], 0, inplace=True) # , '-'
        X_train_df.fillna(value=0, axis=1, inplace=True)
        cat_attribs = ["service"] # "state",
        # ord_attribs = ["stime", "ltime"]
        """ numeric_attribs = ["dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "sload", "dload", "spkts", "dpkts", 
                        "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "transdepth", "resbdylen", "sjit", "djit",
                        "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat", "issmipsports", "ctstatettl",
                        "ctflwhttpmthd", "isftplogin", "ctftpcmd", "cssrvsrc", "ctsrvdst", "ctdstltm", "ctsrcltm", 
                        "ctsrcdportltm", "ctdstsportltm", "ctdstsrcltm"] """
        if self.protocol=='tcp':
            numeric_attribs = ["dur", "sbytes", "dbytes", "spkts", "dpkts"] # , "swin", "dwin", "stcpb", "dtcpb"] # TODO: check shape vs above version
            # sttl, dttl
        elif self.protocol=='udp':
            numeric_attribs = ["dur", "sbytes", "dbytes", "spkts", "dpkts"] # TODO: check shape vs above version
        else:
            print("Uknown protocol. Exiting ...")
            return
        # numeric_cols = list(selector(dtype_include=["int", "float"])(X_train_df[numeric_attribs]))
        ordinal_transformer = Pipeline(steps=[
            ('ordinal', OrdinalEncoder())
        ])
        categorical_transformer = Pipeline(steps=[
            ('to_string', FunctionTransformer(lambda x: x.astype(str), validate=False, accept_sparse=True)),
            ('onehot', OneHotEncoder(sparse_output=True, handle_unknown="ignore"))
        ])
        numeric_transformer = Pipeline(steps=[
            ('to_numeric', FunctionTransformer(validate=False, accept_sparse=True)),
            ('scaler', StandardScaler())
        ])
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, numeric_attribs),  # Specify numerical features
                # ("ord", ordinal_transformer, ord_attribs),
                ("cat", categorical_transformer, cat_attribs),
                ]) 
        X_train = preprocessor.fit_transform(X_train_df)#.toarray()
        if hasattr(X_train, 'toarray'): # Apply toarray() if data is a sparse matrix
            X_train = X_train.toarray()
        X_train = np.array(X_train).astype(np.float32) # astype(np.int32) # .astype(np.float32) # np.array(train_data).astype(np.float32) # astype(np.int32) # .astype(np.float32)
        print("X_train.shape: ", X_train.shape)
        return X_train
    
    def get_unsw_binary_class_labels(self, df):
        label_dict = {"0": "Normal",
                      "1": "Attack"
                    }
        binary_labels = []
        label_list = df['label'].to_list()
        for key in label_list:
            value = label_dict[key]
            binary_labels.append(value)
        # print("binary_labels: \n", binary_labels) # Note: 'Normal', 'Attack' values returned, need label encoding.
        return binary_labels, label_dict
    
    def get_unsw_multi_class_labels(self, df):
        traffic_classes = df['attackcat'].unique()
        label_dict = {}
        label_counter = 0
        for i in traffic_classes:
            label_dict[label_counter] = i
            label_counter += 1
        label_list = df['attackcat'].to_list()
        # print("label_list: \n", label_list) # Note: 'Normal', 'DoS', "Exploits", ... values returned, need label encoding.
        return label_list, label_dict   
    
    def get_payload_df(self, protocol='tcp'):
        tbl_name = protocol + "_pcap_labeled_payload_unique"
        engine = create_engine(f"postgresql+psycopg2://{self.db_user}:{self.db_pwd}@{self.db_host}:{self.db_port}/{self.db_name}")
        metadata = MetaData()
        metadata.bind = engine
        query = "SELECT OCTET_LENGTH(payload) AS payload_length, attackcat, label FROM " + tbl_name + ";"
        with engine.begin() as connection:
            db_df = pd.read_sql(query, con=connection)
            return db_df
    
    def get_payload_binary(self, protocol):
        df = self.get_payload_df(protocol=protocol)
        replacements = {'0': 'Normal', '1': 'Attack'}
        df.replace(replacements, inplace=True)
        return df
        
    def plot_payload_binary(self, protocol):
        sns.set_theme(style="ticks")
        fig, ax = plt.subplots(figsize=(7, 5))
        df = self.get_payload_binary(protocol=protocol)
        sns.despine(fig)
        sns.histplot(
            df,
            x="payload_length",
            stat='count',
            bins=25,
            fill=True,
            # log_scale = True,
            hue='label',
            alpha = 0.5,
            # kde=True,
        )
        ax.xaxis.set_major_formatter(mpl.ticker.ScalarFormatter())
        ax.set(yscale="log")
        ax.set_xlabel("Payload size (bytes)") # r'\textit{Payload length (bytes)}'
        ax.set_ylabel("Number of packets (log scale)") # r'\textit{Number of packets (log)}'
        sns.move_legend(ax, "upper center", bbox_to_anchor=(0.5, 0.8), ncol=2, title=None, frameon=False,)
        fig.tight_layout()
        file_name = os.path.join('/app/results/', f"{protocol}_binary_payload_byte_distribution.pdf")
        fig.savefig(file_name)
        plt.close()
    
    def plot_payload_multiattack(self, protocol):
        sns.set_theme(style="ticks")
        fig, ax = plt.subplots(figsize=(7, 5))
        df = self.get_payload_df(protocol=protocol)
        sns.despine(fig)
        sns.histplot(
            df,
            x="payload_length", # payloadlength
            stat='count',
            bins=25,
            fill=False,
            # log_scale = True,
            hue='attackcat',
            # alpha = 0.7,
            # kde=True,
        )
        ax.xaxis.set_major_formatter(mpl.ticker.ScalarFormatter())
        ax.set(yscale="log")
        ax.set_xlabel("Payload size (bytes)") # r'\textit{Payload length (bytes)}'
        ax.set_ylabel("Number of packets (log scale)") # r'\textit{Number of packets (log)}'
        sns.move_legend(ax, "upper center", bbox_to_anchor=(0.55, 1.1), ncol=2, title=None, frameon=False,)
        fig.tight_layout()
        file_name = os.path.join('/app/results/', f"{protocol}_multiattack_payload_byte_distribution.pdf")
        fig.savefig(file_name)
        plt.close()
    
    def flow_data_generator(self, dataset='unsw', data_percentage=10, protocol='tcp'):
        engine = create_engine(f"postgresql+psycopg2://{self.db_user}:{self.db_pwd}@{self.db_host}:{self.db_port}/{self.db_name}")
        metadata = MetaData()
        metadata.bind = engine
        if dataset == "unsw":
            label_tbl_name = 'unsw_nb15_csv_features_cleaned_unique'
            label_tbl = Table(label_tbl_name, metadata,
                            Column('id', Integer, primary_key=True), # autoincrement=True), 
                            Column('srcip', String),
                            Column('sport', String),
                            Column('dstip', String), 
                            Column('dport', String), 
                            Column('proto', String), 
                            Column('state', String),
                            Column('dur', String), 
                            Column('sbytes', String), 
                            Column('dbytes', String), 
                            Column('sttl', String), 
                            Column('dttl', String), 
                            Column('sloss', String), 
                            Column('dloss', String), 
                            Column('service', String),
                            Column('sload', String), 
                            Column('dload', String), 
                            Column('spkts', String), 
                            Column('dpkts', String),
                            Column('swin', String), 
                            Column('dwin', String), 
                            Column('stcpb', String), 
                            Column('dtcpb', String),
                            Column('smeansz', String), 
                            Column('dmeansz', String), 
                            Column('transdepth', String), 
                            Column('resbdylen', String), 
                            Column('sjit', String), 
                            Column('djit', String), 
                            Column('stime', String), 
                            Column('ltime', String), 
                            Column('sintpkt', String), 
                            Column('dintpkt', String), 
                            Column('tcprtt', String),
                            Column('synack', String), 
                            Column('ackdat', String), 
                            Column('issmipsports', String), 
                            Column('ctstatettl', String),
                            Column('ctflwhttpmthd', String), 
                            Column('isftplogin', String), 
                            Column('ctftpcmd', String), 
                            Column('cssrvsrc', String),
                            Column('ctsrvdst', String), 
                            Column('ctdstltm', String), 
                            Column('ctsrcltm', String), 
                            Column('ctsrcdportltm', String),
                            Column('ctdstsportltm', String), 
                            Column('ctdstsrcltm', String), 
                            Column('attackcat', String), 
                            Column('label', String))
            label_tbl.create(bind=engine, checkfirst=True)
            if protocol == 'tcp':
                payload_tbl_name = "tcp_pcap_labeled_payload_unique"
            elif protocol == 'udp':
                payload_tbl_name = "udp_pcap_labeled_payload_unique"
            else:
                print("Unknown protocol. Exiting ...")
                return
            payload_tbl = Table(payload_tbl_name, metadata,
                            Column('id', Integer, primary_key=True), # autoincrement=True),
                            Column('stimepcap', String), 
                            Column('srcip', String),
                            Column('sport', String), 
                            Column('dstip', String), 
                            Column('dport', String), 
                            Column('payload', Text),
                            Column('proto', String), 
                            Column('state', String),
                            Column('dur', String), 
                            Column('sbytes', String), 
                            Column('dbytes', String), 
                            Column('sttl', String), 
                            Column('dttl', String), 
                            Column('sloss', String), 
                            Column('dloss', String), 
                            Column('service', String),
                            Column('sload', String), 
                            Column('dload', String), 
                            Column('spkts', String), 
                            Column('dpkts', String),
                            Column('swin', String), 
                            Column('dwin', String), 
                            Column('stcpb', String), 
                            Column('dtcpb', String),
                            Column('smeansz', String), 
                            Column('dmeansz', String), 
                            Column('transdepth', String), 
                            Column('resbdylen', String), 
                            Column('sjit', String), 
                            Column('djit', String), 
                            Column('stime', String), 
                            Column('ltime', String), 
                            Column('sintpkt', String), 
                            Column('dintpkt', String), 
                            Column('tcprtt', String),
                            Column('synack', String), 
                            Column('ackdat', String), 
                            Column('issmipsports', String), 
                            Column('ctstatettl', String),
                            Column('ctflwhttpmthd', String), 
                            Column('isftplogin', String), 
                            Column('ctftpcmd', String), 
                            Column('cssrvsrc', String),
                            Column('ctsrvdst', String), 
                            Column('ctdstltm', String), 
                            Column('ctsrcltm', String), 
                            Column('ctsrcdportltm', String),
                            Column('ctdstsportltm', String), 
                            Column('ctdstsrcltm', String), 
                            Column('attackcat', String), 
                            Column('label', String))
            payload_tbl.create(bind=engine, checkfirst=True)
        else:
            print("Unknown dataset. Dataset has to be 'unsw'. Exiting ...")
            return
        
        with engine.connect() as connection:
            if dataset == 'unsw':
                seed_value = 42
                connection.execute(func.text(f"SELECT setseed({seed_value})"))
                condition = (
                    (func.split_part(payload_tbl.c.stimepcap, '.', 1)  == label_tbl.c.stime) &  # Taking the non-decimal part of pcap timestamp to match stime precision
                    (payload_tbl.c.srcip == label_tbl.c.srcip) & 
                    (payload_tbl.c.sport == label_tbl.c.sport) & 
                    (payload_tbl.c.dstip == label_tbl.c.dstip) & 
                    (payload_tbl.c.dport == label_tbl.c.dport) & 
                    (payload_tbl.c.proto == protocol) &
                    (label_tbl.c.proto == protocol) &
                    (payload_tbl.c.payload != '')
                )
                count_subquery = ( # Build the subquery to calculate the total count of rows
                    select(func.count())
                    .select_from(label_tbl.join(payload_tbl, condition))
                    .scalar_subquery()
                )
                num_rows_to_select = func.ceil(count_subquery * data_percentage / 100) # Calculate the number of rows to select based on the fixed percentage
                query = select(label_tbl).join(payload_tbl, condition).order_by(func.random()).limit(num_rows_to_select)
                rows = connection.execute(query).fetchall()
                if self.protocol=='tcp' or self.protocol=='udp':
                        df = pd.DataFrame(rows, columns=unsw_flow_columns)
                        X = self.get_unsw_flow_data(df=df)
                        if self.class_type == 'binary':
                            y, _ = self.get_unsw_binary_class_labels(df=df)
                        elif self.class_type == 'multiclass':
                            y, _ = self.get_unsw_multi_class_labels(df=df)
                        else:
                            print("Unknown class type. Exiting ...")
                            return
                else:
                    print("Unknown protocol. Exiting ...")
                    return
            else:
                print("Unknown dataset. Dataset has to be 'unsw'. Exiting ...")
                return
            samples_labels = list(zip(X,y))
            random.shuffle(samples_labels)
            X, y = zip(*samples_labels)
            X = np.asarray(X) # , dtype=np.32)
            y = np.asarray(y)
            return X, y, df
    
    def payload_data_generator(self, dataset='unsw', data_percentage=10, protocol='tcp', num_bytes=32):
        engine = create_engine(f"postgresql+psycopg2://{self.db_user}:{self.db_pwd}@{self.db_host}:{self.db_port}/{self.db_name}")
        metadata = MetaData()
        metadata.bind = engine
        if dataset == "unsw":
            label_tbl_name = 'unsw_nb15_csv_features_cleaned_unique'
            label_tbl = Table(label_tbl_name, metadata,
                            Column('id', Integer, primary_key=True), # autoincrement=True),
                            Column('srcip', String),
                            Column('sport', String),
                            Column('dstip', String), 
                            Column('dport', String), 
                            Column('proto', String), 
                            Column('state', String),
                            Column('dur', String), 
                            Column('sbytes', String), 
                            Column('dbytes', String), 
                            Column('sttl', String), 
                            Column('dttl', String), 
                            Column('sloss', String), 
                            Column('dloss', String), 
                            Column('service', String),
                            Column('sload', String), 
                            Column('dload', String), 
                            Column('spkts', String), 
                            Column('dpkts', String),
                            Column('swin', String), 
                            Column('dwin', String), 
                            Column('stcpb', String), 
                            Column('dtcpb', String),
                            Column('smeansz', String), 
                            Column('dmeansz', String), 
                            Column('transdepth', String), 
                            Column('resbdylen', String), 
                            Column('sjit', String), 
                            Column('djit', String), 
                            Column('stime', String), 
                            Column('ltime', String), 
                            Column('sintpkt', String), 
                            Column('dintpkt', String), 
                            Column('tcprtt', String),
                            Column('synack', String), 
                            Column('ackdat', String), 
                            Column('issmipsports', String), 
                            Column('ctstatettl', String),
                            Column('ctflwhttpmthd', String), 
                            Column('isftplogin', String), 
                            Column('ctftpcmd', String), 
                            Column('cssrvsrc', String),
                            Column('ctsrvdst', String), 
                            Column('ctdstltm', String), 
                            Column('ctsrcltm', String), 
                            Column('ctsrcdportltm', String),
                            Column('ctdstsportltm', String), 
                            Column('ctdstsrcltm', String), 
                            Column('attackcat', String), 
                            Column('label', String))
            label_tbl.create(bind=engine, checkfirst=True)
            if protocol == 'tcp':
                payload_tbl_name = "tcp_pcap_labeled_payload_unique"
            elif protocol == 'udp':
                payload_tbl_name = "udp_pcap_labeled_payload_unique"
            else:
                print("Unknown protocol. Exiting ...")
                return
            payload_tbl = Table(payload_tbl_name, metadata,
                            Column('id', Integer, primary_key=True),
                            Column('stimepcap', String), 
                            Column('srcip', String),
                            Column('sport', String), 
                            Column('dstip', String), 
                            Column('dport', String), 
                            Column('payload', Text),
                            Column('proto', String), 
                            Column('state', String),
                            Column('dur', String), 
                            Column('sbytes', String), 
                            Column('dbytes', String), 
                            Column('sttl', String), 
                            Column('dttl', String), 
                            Column('sloss', String), 
                            Column('dloss', String), 
                            Column('service', String),
                            Column('sload', String), 
                            Column('dload', String), 
                            Column('spkts', String), 
                            Column('dpkts', String),
                            Column('swin', String), 
                            Column('dwin', String), 
                            Column('stcpb', String), 
                            Column('dtcpb', String),
                            Column('smeansz', String), 
                            Column('dmeansz', String), 
                            Column('transdepth', String), 
                            Column('resbdylen', String), 
                            Column('sjit', String), 
                            Column('djit', String), 
                            Column('stime', String), 
                            Column('ltime', String), 
                            Column('sintpkt', String), 
                            Column('dintpkt', String), 
                            Column('tcprtt', String),
                            Column('synack', String), 
                            Column('ackdat', String), 
                            Column('issmipsports', String), 
                            Column('ctstatettl', String),
                            Column('ctflwhttpmthd', String), 
                            Column('isftplogin', String), 
                            Column('ctftpcmd', String), 
                            Column('cssrvsrc', String),
                            Column('ctsrvdst', String), 
                            Column('ctdstltm', String), 
                            Column('ctsrcltm', String), 
                            Column('ctsrcdportltm', String),
                            Column('ctdstsportltm', String), 
                            Column('ctdstsrcltm', String), 
                            Column('attackcat', String), 
                            Column('label', String))
            payload_tbl.create(bind=engine, checkfirst=True)
        else:
            print("Unknown dataset. Dataset has to be 'unsw'. Exiting ...")
            return
        
        with engine.connect() as connection:
            if dataset=='unsw':
                condition = (
                    (func.split_part(payload_tbl.c.stimepcap, '.', 1)  == label_tbl.c.stime) &  # Taking the non-decimal part of pcap timestamp to match stime precision
                    (payload_tbl.c.srcip == label_tbl.c.srcip) & 
                    (payload_tbl.c.sport == label_tbl.c.sport) & 
                    (payload_tbl.c.dstip == label_tbl.c.dstip) & 
                    (payload_tbl.c.dport == label_tbl.c.dport) &
                    (payload_tbl.c.proto == protocol) &
                    (label_tbl.c.proto == protocol) &
                    (payload_tbl.c.payload != '')
                )
                seed_value = 42
                connection.execute(func.text(f"SELECT setseed({seed_value})"))
                count_subquery = ( # Build the subquery to calculate the total count of rows
                    select(func.count())
                    .select_from(label_tbl.join(payload_tbl, condition))
                    .scalar_subquery()
                )
                num_rows_to_select = func.ceil(count_subquery * data_percentage / 100)
                query = select(payload_tbl.c.id, payload_tbl.c.payload, payload_tbl.c.attackcat, payload_tbl.c.label).join(label_tbl, condition).order_by(func.random()).limit(num_rows_to_select)
                rows = connection.execute(query).fetchall()
                if self.protocol=='tcp' or self.protocol=='udp':
                    df = pd.DataFrame(rows, columns=["id", "payload", "attackcat", "label"])
                    X = self.get_payload_data(df=df, num_bytes=num_bytes)
                    if self.class_type == 'binary':
                        y, _ = self.get_unsw_binary_class_labels(df=df)
                    elif self.class_type == 'multiclass':
                        y, _ = self.get_unsw_multi_class_labels(df=df)
                    else:
                        print("Unknown class type. Exiting ...")
                        return
                else:
                    print("Unknown protocol. Exiting ...")
                    return
            else:
                print("Unknown dataset. Dataset has to be 'unsw'. Exiting ...")
                return
        samples_labels = list(zip(X,y))
        random.shuffle(samples_labels)
        X, y = zip(*samples_labels)
        X = np.asarray(X)#, dtype=np.int32)
        y = np.asarray(y)
        return X, y, df