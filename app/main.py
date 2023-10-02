import numpy as np
import DataManager as dm
import FlowClassifier as fc

def main():
    data_manager = dm.DataManager()
    data_manager.merge_unsw_nb15_csvs()
    data_manager.update_attackcat_unsw_nb15_csv()
    data_manager.insert_unsw_csv_to_table()
    data_manager.get_non_redundant_unsw_csv() 
    data_manager.extract_data_from_unsw_pcaps(protocol='tcp')
    data_manager.insert_unsw_pcap_data_to_table(protocol='tcp')
    data_manager.create_labeled_payloads_for_unsw(protocol='tcp')
    data_manager.extract_data_from_unsw_pcaps(protocol='udp')
    data_manager.insert_unsw_pcap_data_to_table(protocol='udp')
    data_manager.create_labeled_payloads_for_unsw(protocol='udp')
    data_manager.plot_payload_binary(protocol='tcp')
    data_manager.plot_payload_multiattack(protocol='tcp')
    data_manager.plot_payload_binary(protocol='udp')
    data_manager.plot_payload_multiattack(protocol='udp')
    flow = fc.FlowClassifier(dataset='unsw', protocol='tcp', class_type='binary')
    flow.rf_train_and_test(dataset='unsw', data_percentage=10, num_bytes=32)
    flow = fc.FlowClassifier(dataset='unsw', protocol='tcp', class_type='multiclass') 
    flow.rf_train_and_test(dataset='unsw', data_percentage=10, num_bytes=32)
    flow = fc.FlowClassifier(dataset='unsw', protocol='udp', class_type='binary')
    flow.rf_train_and_test(dataset='unsw', data_percentage=100, num_bytes=32)
    flow = fc.FlowClassifier(dataset='unsw', protocol='udp', class_type='multiclass') 
    flow.rf_train_and_test(dataset='unsw', data_percentage=100, num_bytes=32)

if __name__ == "__main__":
    main()