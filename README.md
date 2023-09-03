# Specify the URL of the file(s) to download --> download and 
# Place .pcap files in feb_pcap, jan_pcap, cicids2017_pcap subdirectories which are themselves 
# in the same root directory as this program. Links to download the PCAP files of the two datasets is below.
dataset_urls = [
                'http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/PCAPs/', # CIC-IDS-2017 PCAP files
                'https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys?path=%2FUNSW-NB15%20-%20pcap%20files' # UNSW-NB15 PCAP files
            ]
# TODO: # '-e', 'data', --> payload data even if not TCP
# TODO: # tshark -v --> 3.6.2 (Dockerfile) # '-e', 'data', --> payload data even if not UDP
# tshark -Y udp -T fields -e frame.time_epoch -e ip.src -E occurrence=f -e udp.srcport -e ip.dst -E occurrence=f -e udp.dstport -e udp.payload -E separator='|' -r 1.pcap
# Caution: appending mode so program should be run only once as data would repeat.
### Create table and insert values from pcap_features.csv file
# Note: there are no headers to skip as there is no header row
# TODO: Check for the UNSW-NB15 for required_files.keys() to 
## TODO: check double "_" in hybrid_nids
# Taking the non-decimal part of pcap timestamp to match stime (second?) precision
# data_manager.extract_data_from_unsw_pcaps(protocol='udp') # TODO--> Done. tshark version problem. version 3.6.2 works under ubuntu base.