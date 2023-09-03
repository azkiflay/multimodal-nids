from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score
from sklearn.metrics import roc_curve, roc_auc_score, auc
from sklearn.preprocessing import label_binarize
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from itertools import cycle
import joblib
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import numpy as np
import pandas as pd
plt.style.use("seaborn-paper") # Options: bmh, classic, dark_background, fivethirtyeight, ggplot,
                    # grayscale,  seaborn-bright,  seaborn-colorblind, seaborn-dark,
                    #  seaborn-dark-palette,  seaborn-darkgrid,  seaborn-deep,
                    #  seaborn-muted,  seaborn-notebook,  seaborn-pastel,
                    #  seaborn-poster,  seaborn-talk, seaborn-ticks,
                    #  seaborn-white,  seaborn-whitegrid
plt.rcParams['axes.formatter.useoffset'] = True
from matplotlib import rc
rc('text', usetex=True)
import matplotlib
matplotlib.rcParams['text.usetex'] = True
plt.rcParams['font.family'] = 'DeJavu Serif'
plt.rcParams['font.serif'] = ['Times New Roman']
import DataManager as dm
import os
import csv

class FlowClassifier:
    def __init__(self, dataset, protocol, class_type) -> None: # service,
        self.protocol=protocol
        self.class_type=class_type
        self.dataset=dataset
        self.data_manager = dm.DataManager(protocol=self.protocol, class_type=self.class_type)
    
    def rf_train_and_test(self, dataset='unsw', data_percentage=10, num_bytes=32):
        payload_model = RandomForestClassifier(n_estimators=100, criterion='gini', max_depth=None, min_samples_split=2, min_samples_leaf=1, 
                                        min_weight_fraction_leaf=0.0,  max_features='sqrt', max_leaf_nodes=None, min_impurity_decrease=0.0, 
                                        bootstrap=True, oob_score=False, n_jobs=None, random_state=42, verbose=0, warm_start=False,
                                        class_weight=None, ccp_alpha=0.0, max_samples=None)
        flow_model = RandomForestClassifier(n_estimators=100, criterion='gini', max_depth=None, min_samples_split=2, min_samples_leaf=1, 
                                        min_weight_fraction_leaf=0.0,  max_features='sqrt', max_leaf_nodes=None, min_impurity_decrease=0.0, 
                                        bootstrap=True, oob_score=False, n_jobs=None, random_state=42, verbose=0, warm_start=False,
                                        class_weight=None, ccp_alpha=0.0, max_samples=None)
        if dataset=='unsw':
            if self.protocol == 'tcp' or self.protocol == 'udp':
                if self.class_type == 'binary':
                    filename = str(dataset) + "_" + str(self.protocol) + "_binary_model"
                    filename = os.path.join('/app/results/', filename)
                elif self.class_type == 'multiclass':
                    filename = str(dataset) + "_" + str(self.protocol) + "_multiclass_model"
                    filename = os.path.join('/app/results/', filename)
                else:
                    print("Uknown class type. Exiting ...")
                    return
            else:
                print("Uknown protocol. Exiting ...")
                return
            X_flow, y_flow, df = self.data_manager.flow_data_generator(dataset=dataset, data_percentage=data_percentage, protocol=self.protocol)
            X_payload, y_payload, df = self.data_manager.payload_data_generator(dataset=dataset, data_percentage=data_percentage, protocol=self.protocol, num_bytes=num_bytes)
        else:
            print("Unknown dataset. Dataset has to be 'unsw'. Exiting ...")
            return
        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.20, random_state=42)
        X_payload_train, X_payload_test, y_payload_train, y_payload_test = train_test_split(X_payload, y_payload, test_size=0.20, random_state=42)  
        if X_payload_train.shape[0] != y_payload_train.shape[0]:
            print("Error: Number of samples in X_payload_train and y_payload_train do not match. Exiting ...")
            return
        if X_payload_test.shape[0] != y_payload_test.shape[0]:
            print("Error: Number of samples in X_payload_test and y_payload_test do not match. Exiting ...")
            return
        if self.class_type == 'binary':
            flow_labels = list(y_flow_train.tolist() + y_flow_test.tolist())
            print("np.unique(flow_labels): ", np.unique(flow_labels))
            payload_labels = list(y_payload_train.tolist() + y_payload_test.tolist())
            print("np.unique(payload_labels): ", np.unique(payload_labels))
            encoder_flow = LabelEncoder()
            encoder_flow.fit(flow_labels)
            y_flow_train = encoder_flow.transform(y_flow_train)
            y_flow_test = encoder_flow.transform(y_flow_test)
            encoder_payload = LabelEncoder()
            encoder_payload.fit(payload_labels)
            y_payload_train = encoder_payload.transform(y_payload_train)
            y_payload_test = encoder_payload.transform(y_payload_test)
        elif self.class_type == 'multiclass':
            flow_labels = list(y_flow_train.tolist() + y_flow_test.tolist())
            print("np.unique(flow_labels): ", np.unique(flow_labels))
            payload_labels = list(y_payload_train.tolist() + y_payload_test.tolist())
            print("np.unique(payload_labels): ", np.unique(payload_labels))
            encoder_flow = LabelEncoder()
            encoder_flow.fit(flow_labels)
            encoder_payload = LabelEncoder()
            encoder_payload.fit(payload_labels)
            y_flow_train = encoder_flow.transform(y_flow_train)
            y_flow_test = encoder_flow.transform(y_flow_test)
            y_payload_train = encoder_payload.transform(y_payload_train)
            y_payload_test = encoder_payload.transform(y_payload_test)
        else:
            print("Uknown class type. Exiting ...")
            return
        # Training phase
        payload_model.fit(X_payload_train, y_payload_train)
        flow_model.fit(X_flow_train, y_flow_train)
        joblib.dump(payload_model, filename + "_payload.joblib", compress=3)
        joblib.dump(flow_model, filename + "_flow.joblib", compress=3)
        print("=== Models Saved at: ", filename + "_payload.joblib", " ", filename + "_flow.joblib", " ===")
        # Testing phase
        payload_model = joblib.load(filename + "_payload.joblib")
        flow_model = joblib.load(filename + "_flow.joblib")
        if dataset=='unsw':
            if self.protocol == 'tcp' or self.protocol == 'udp':
                if self.class_type == 'binary':
                    _, binary_class_dict = self.data_manager.get_unsw_binary_class_labels(df=df)
                    filename = str(dataset) + "_" + str(self.protocol) + "_" + "_binary_model"
                    filename = os.path.join('/app/results/', filename)
                    for key, value in binary_class_dict.items():
                            print("Binary Traffic Class ", value, " --> ", key)
                
                    print("Saving Binary Ensemble-NIDS scores.")
                    self.save_binary_scores_vote(flow_model, payload_model, X_flow_test, X_payload_test, y_flow_test, binary_class_dict, 0.6, 0.4)
                    binary_scores = self.get_binary_scores_vote(flow_model, payload_model, X_flow_test, X_payload_test, y_flow_test, 0.6, 0.4)
                    print("Ensemble_NIDS binary_scores: \n", binary_scores)
                    self.plot_binary_ROC_curve_vote(flow_model, payload_model, X_flow_test, X_payload_test, y_flow_test, 0.6, 0.4)
                    self.plot_binary_confusion_matrix_vote(flow_model, payload_model, X_flow_test, X_payload_test, y_flow_test, encoder_flow, 0.6, 0.4)
                    self.get_binary_fpr_vote(flow_model, payload_model, X_flow_test, X_payload_test, y_flow_test, 0.6, 0.4)
                elif self.class_type == 'multiclass':
                    filename = str(dataset) + "_" + str(self.protocol) + "_multiclass_model"
                    filename = os.path.join('/app/results/', filename)
                    _, multiclass_dict = self.data_manager.get_unsw_multi_class_labels(df=df)
                    for key, value in multiclass_dict.items():
                        print("Traffic class ", value, " --> ", key)
                    print("Plotting Ensemble-NIDS Multiclass ROC Curves.")
                    self.plot_roc_auc_multiclass_vote(flow_model, payload_model, X_flow_test, X_payload_test, y_flow_test, encoder_flow, 0.6, 0.4)
                    multiclass_scores = self.get_multiclass_scores_vote(flow_model, payload_model, X_flow_test, X_payload_test, y_flow_test, 0.6, 0.4)
                    print(f"Model Ensemble-NIDS metrics: \n", multiclass_scores)
                    self.plot_multiclass_confusion_matrix_vote(flow_model, payload_model, X_flow_test, X_payload_test, y_flow_test, encoder_flow, 0.6, 0.4)
                    self.get_multiclass_fpr_vote(flow_model, payload_model, X_flow_test, X_payload_test, y_flow_test, encoder_flow, 0.6, 0.4)
                else:
                    print("Uknown class type. Exiting ...")
                    return
            else:
                print("Uknown protocol. Exiting ...")
                return 
        else:
            print("Uknown dataset. Exiting ...")
            return

    def predict_proba_vote_binary(self, flow_model, payload_model, X_flow, X_payload, flow_scale=0.5, payload_scale=0.5):
        y_proba_flow = flow_model.predict_proba(X_flow)
        y_proba_payload = payload_model.predict_proba(X_payload)
        if y_proba_flow.shape[1] != 2 or y_proba_payload.shape[1] != 2:
            raise ValueError("Both flow_model and payload_model must be binary classifiers.")
        weighted_probs_flow = y_proba_flow[:, 1] * flow_scale  # Assuming binary classification, use the probabilities of class 1 (positive class)
        weighted_probs_payload = y_proba_payload[:, 1] * payload_scale
        aggregated_probs = weighted_probs_flow + weighted_probs_payload
        final_probs = np.column_stack([1 - aggregated_probs, aggregated_probs]) # Combine the probabilities to form the final matrix of shape (n_samples, n_classes)
        return final_probs
    
    def predict_vote_binary(self, flow_model, payload_model, flow_data, payload_data, flow_scale=0.5, payload_scale=0.5):
        final_probs = self.predict_proba_vote_binary(flow_model, payload_model, flow_data, payload_data, flow_scale, payload_scale)
        final_classes = np.argmax(final_probs, axis=1)
        return final_classes
    
    def predict_proba_vote_multiclass(self, flow_model, payload_model, X_flow, X_payload, flow_scale=0.5, payload_scale=0.5):
        y_proba_flow = flow_model.predict_proba(X_flow)
        y_proba_payload = payload_model.predict_proba(X_payload)
        if y_proba_flow.shape[1] != y_proba_payload.shape[1]:
            raise ValueError("The number of classes in the predictions of flow_model and payload_model must be the same.")
        weighted_probs_flow = y_proba_flow * flow_scale
        weighted_probs_payload = y_proba_payload * payload_scale
        aggregated_probs = weighted_probs_flow + weighted_probs_payload
        return aggregated_probs
    
    def predict_vote_multiclass(self, flow_model, payload_model, X_flow, X_payload, flow_scale=0.5, payload_scale=0.5):
        final_probs = self.predict_proba_vote_multiclass(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)
        final_classes = np.argmax(final_probs, axis=1)
        return final_classes

    def get_binary_scores_vote(self, flow_model, payload_model, X_flow, X_payload, y, flow_scale=0.5, payload_scale=0.5):
        y_pred = self.predict_vote_binary(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)
        accuracy_flow = accuracy_score(y, y_pred)
        precision_flow = precision_score(y, y_pred)
        recall_flow = recall_score(y, y_pred)
        f1_flow = f1_score(y, y_pred)
        metrics = {
            "Accuracy": accuracy_flow,
            "Precision": precision_flow,
            "Recall": recall_flow,
            "F1": f1_flow
        }
        metrics_df = pd.DataFrame(metrics, index=[0])
        model_name = "Ensemble_NIDS"
        filename = os.path.join('/app/results/', f"{model_name}_{self.dataset}_{self.protocol}_{self.class_type}_accuracy_metrics.csv")
        metrics_df.to_csv(filename, index=False)
        print(f"Binary scores for {model_name} saved at {filename}")
        return metrics

    def save_binary_scores_vote(self, flow_model, payload_model, X_flow, X_payload, y, class_dict, flow_scale=0.5, payload_scale=0.5):
        y_pred = self.predict_vote_binary(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)
        precision, recall, f1, support = precision_recall_fscore_support(y, y_pred)
        weighted_avg_precision = precision_score(y, y_pred, average='weighted', zero_division=0.0)
        weighted_avg_recall = recall_score(y, y_pred, average='weighted', zero_division=0.0)
        weighted_avg_f1 = f1_score(y, y_pred, average='weighted', zero_division=0.0)
        macro_avg_precision = precision_score(y, y_pred, average='macro', zero_division=0.0)
        macro_avg_recall = recall_score(y, y_pred, average='macro', zero_division=0.0)
        macro_avg_f1 = f1_score(y, y_pred, average='macro', zero_division=0.0)
        micro_avg_precision = precision_score(y, y_pred, average='micro', zero_division=0.0)
        micro_avg_recall = recall_score(y, y_pred, average='micro', zero_division=0.0)
        micro_avg_f1 = f1_score(y, y_pred, average='micro', zero_division=0.0)
        df = pd.DataFrame({
            'Class': list(class_dict.values()) + ['Weighted average', 'Macro average', 'Micro average'],
            'Precision': list(precision) + [weighted_avg_precision, macro_avg_precision, micro_avg_precision],
            'Recall': list(recall) + [weighted_avg_recall, macro_avg_recall, micro_avg_recall],
            'F1 score': list(f1) + [weighted_avg_f1, macro_avg_f1, micro_avg_f1],
            'Support': list(support) + [sum(support), '', '']
        })
        df.loc[len(df)] = ['Accuracy', '', '', accuracy_score(y, y_pred), '']
        model_name = "Ensemble_NIDS"
        file_name = os.path.join('/app/results/', f"{model_name}_{self.dataset}_{self.protocol}_{self.class_type}_average_scores.csv")
        df.to_csv(file_name, index=False)
        print(f"Binary scores for {model_name} saved at {file_name}")
    
    def plot_binary_ROC_curve_vote(self, flow_model, payload_model, X_flow, X_payload, y, flow_scale=0.5, payload_scale=0.5):
        font_size = 14
        font_style = 'italic'
        print(f"Plotting binary ROC for Vote-based model...")
        fig, ax = plt.subplots(figsize=(3, 3))
        y_proba = self.predict_proba_vote_binary(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)[:, 1]
        fpr, tpr, thresholds = roc_curve(y, y_proba)
        roc_auc = roc_auc_score(y, y_proba)
        ax.plot(fpr, tpr, linewidth=0.7, alpha=0.8, color='red', label="AUC = {:.2f}".format(roc_auc))
        # ax.set_title(model_name, fontsize=font_size, fontweight='bold', fontstyle=font_style)
        ax.legend(fontsize=font_size-4)
        ax.legend().set_visible(True)
        ax.spines.right.set_visible(False)
        ax.spines.left.set_visible(True)
        ax.spines.top.set_visible(False)
        ax.spines.bottom.set_visible(True)
        ax.spines['bottom'].set_linewidth(0.75)
        ax.spines['left'].set_linewidth(0.75)
        ax.spines['bottom'].set_color('black')
        ax.spines['left'].set_color('black')
        ax.tick_params(axis='both', which='both', labelsize=font_size-4, pad=3, color='black')
        ax.grid(True, linestyle=':', linewidth=0.9) # ax.grid(False) # , linestyle='--', linewidth=0.9)
        ax.set_ylabel(r'\textbf{True Positive Rate (TPR)}', fontsize=font_size-4, fontweight='bold', fontstyle=font_style, labelpad=4)
        ax.set_xlabel(r'\textbf{False Positive Rate (FPR)}', fontsize=font_size-4, fontweight='bold', fontstyle=font_style, labelpad=4)
        plt.subplots_adjust(wspace=0.1, hspace=0.1)
        plt.tight_layout()
        # file_name = model_name + "_" + str(dataset) + "_" + str(self.protocol) + "_" + str(self.class_type) + "_roc.pdf"
        model_name = "Ensemble_NIDS"
        file_name = os.path.join('/app/results/', f"{model_name}_{self.dataset}_{self.protocol}_{self.class_type}_roc.pdf")
        fig.savefig(file_name, dpi=300, bbox_inches='tight', pad_inches=0.05)
        print(f"Binary ROC curve for {model_name} saved at {file_name}")
        plt.close()

    def plot_binary_confusion_matrix_vote(self, flow_model, payload_model, X_flow, X_payload, y, encoder, flow_scale=0.5, payload_scale=0.5):
        font_size = 14
        font_style = 'italic'
        print(f"Plotting binary confusion matrix for Vote-based model ... \n")
        fig, ax = plt.subplots(figsize=(7, 5))
        y_pred = self.predict_vote_binary(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)
        y_test_original = encoder.inverse_transform(y)
        y_pred_original = encoder.inverse_transform(y_pred)
        y_test_numeric = encoder.transform(y_test_original)
        y_pred_numeric = encoder.transform(y_pred_original)
        cm = confusion_matrix(y_test_numeric, y_pred_numeric)
        codes = ['A', 'B'] # Create a list of alphabets for tick labels
        label_legend = [(alpha, label) for alpha, label in zip(codes, encoder.classes_)]
        display_labels = [alpha for alpha, _ in label_legend]
        cm_display = ConfusionMatrixDisplay(cm, display_labels=display_labels)
        cm_display.plot(cmap='Blues', ax=ax) # cmap='binary', cmap='viridis', cmap='cividis', cmap='plasma', cmap='inferno'
        handles = [plt.Line2D([0], [0], linestyle='', label=f"{num} - {label}") for num, label in label_legend]
        ax.legend(handles=handles, bbox_to_anchor=(0.5, -0.2), loc='lower center', ncol=2, frameon=False, fontsize=font_size-4)
        # ax.get_images()[0].colorbar.remove() # Hides heatmap legend for the confusion matrix
        ax.tick_params(axis='both', which='both', labelsize=font_size-6, pad=3, color='black')
        # ax.set_title(model_name, fontsize=font_size, fontweight='bold', fontstyle=font_style)
        ax.set_xlabel(r'\textbf{Predicted Traffic Class}', fontsize=font_size-4, fontweight='bold', fontstyle=font_style, labelpad=4)
        ax.set_ylabel(r'\textbf{True Traffic Class}', fontsize=font_size-4, fontweight='bold', fontstyle=font_style, labelpad=4)
        ax.grid(False)
        # Set alphabets as x and y tick labels
        ax.set_xticks(np.arange(len(codes)))
        ax.set_yticks(np.arange(len(codes)))
        ax.set_xticklabels(codes, fontsize=font_size-4)
        ax.set_yticklabels(codes, fontsize=font_size-4)
        plt.subplots_adjust(wspace=0.1, hspace=0.1)
        plt.tight_layout()
        model_name = "Ensemble_NIDS"
        file_name = os.path.join('/app/results/', f"{model_name}_{self.dataset}_{self.protocol}_{self.class_type}_confusion_matrix.pdf")
        fig.savefig(file_name, dpi=300, bbox_inches='tight', pad_inches=0.05)
        print(f"Binary confusion matrix for {model_name} saved at {file_name}")
        plt.close()

    def get_binary_fpr_vote(self, flow_model, payload_model, X_flow, X_payload, y, flow_scale=0.5, payload_scale=0.5):
        results = []
        results.append(["Model Name", "False Positive Rate (FPR)"])
        model_name = "Ensemble_NIDS"
        print(f"Binary FPR for {model_name}.\n")
        y_pred = self.predict_vote_binary(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)
        tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
        fpr = fp / (fp + tn)  # Compute false alarm rate
        print(f"{model_name} False Positive Rate (FPR):\n", fpr)
        results.append([model_name, fpr])
        file_name = os.path.join('/app/results/', f"{model_name}_{self.dataset}_{self.protocol}_{self.class_type}_fpr.csv")
        with open(file_name, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerows(results)
        print(f"Binary FPR results for Vote-based model saved at {file_name}.")

    def get_multiclass_scores_vote(self, flow_model, payload_model, X_flow, X_payload, y, flow_scale=0.5, payload_scale=0.5):
        y_pred = self.predict_vote_multiclass(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)
        accuracy = accuracy_score(y, y_pred)
        precision = precision_score(y, y_pred, average='macro')
        recall = recall_score(y, y_pred, average='macro')
        f1 = f1_score(y, y_pred, average='macro')
        metrics = {
            'Accuracy': accuracy,
            'Precision': precision,
            'Recall': recall,
            'F1': f1
        }
        metrics_df = pd.DataFrame(metrics, index=[0]) # Save the metrics to a CSV file
        model_name = "Ensemble_NIDS"
        file_name = os.path.join('/app/results/', f"{model_name}_{self.dataset}_{self.protocol}_{self.class_type}_accuracy_metrics.csv")
        metrics_df.to_csv(file_name, index=False)
        print(f"Multiclass scores for {model_name} saved at {file_name}")
        return metrics
    
    def plot_roc_auc_multiclass_vote(self, flow_model, payload_model, X_flow, X_payload, y, encoder, flow_scale=0.5, payload_scale=0.5):
        print(f"Plotting Multiclass ROC Curves ...")
        font_size = 16
        font_style = 'italic'
        y_test_bin = label_binarize(y, classes=np.unique(y))
        y_score = self.predict_proba_vote_multiclass(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)
        fpr = dict() 
        tpr = dict()
        roc_auc = dict()
        n_classes = y_test_bin.shape[1]
        for i in range(n_classes):
            fpr[i], tpr[i], _ = roc_curve(y_test_bin[:, i], y_score[:, i])
            roc_auc[i] = auc(fpr[i], tpr[i])
        fpr["micro"], tpr["micro"], _ = roc_curve(y_test_bin.ravel(), y_score.ravel()) # Compute micro-average ROC curve and AUC
        roc_auc["micro"] = auc(fpr["micro"], tpr["micro"])
        fig, ax = plt.subplots(figsize=(5,4)) # figsize=(7,5)) # figsize=(4,3)
        colors = cycle(['blue', 'black', 'green', 'orange', 'purple', 'brown', 'pink', 'gray', 'olive', 'cyan']) # colors = cycle(["#E69F00", "#56B4E9", "#009E73", "#0072B2", "#D55E00", "#CC79A7", "#F0E442", 'red', 'blue', 'black']) 
        y_score_categorical = encoder.inverse_transform(np.unique(y))
        for i, color in zip(range(n_classes), colors):
            label_name = y_score_categorical[i] # encoder.classes_[i]
            ax.plot(fpr[i], tpr[i], linewidth=0.9, alpha=0.8, color=color, label='{0} (AUC = {1:0.2f})'.format(label_name, roc_auc[i])) # label=str(key) + " AUC = {:.2f}".format(roc_auc)
        ax.plot(fpr["micro"], tpr["micro"], alpha=0.6, linestyle='--', color='red', lw=0.8,
                label='Micro-average (AUC = {0:0.2f})'.format(roc_auc["micro"]))
        ax.legend(fontsize=font_size-6)
        ax.legend().set_visible(True)
        ax.spines.right.set_visible(False)
        ax.spines.left.set_visible(True)
        ax.spines.top.set_visible(False)
        ax.spines.bottom.set_visible(True)
        ax.spines['bottom'].set_linewidth(0.75)
        ax.spines['left'].set_linewidth(0.75)
        ax.spines['bottom'].set_color('black')
        ax.spines['left'].set_color('black')
        ax.tick_params(axis='both', which='both', labelsize=font_size-6, pad=3, color='black')
        ax.grid(True, linestyle=':', linewidth=0.9) # ax.grid(False) # , linestyle='--', linewidth=0.9)
        # Set alphabets as x and y tick labels
        ax.set_xticks(np.arange(0, 1.2, 0.2))
        ax.set_yticks(np.arange(0, 1.2, 0.2))
        ax.set_ylabel(r'\textbf{True Positive Rate (TPR)}', fontsize=font_size-6, fontweight='bold', fontstyle=font_style, labelpad=4)
        ax.set_xlabel(r'\textbf{False Positive Rate (FPR)}', fontsize=font_size-6, fontweight='bold', fontstyle=font_style, labelpad=4)
        plt.subplots_adjust(wspace=0.1, hspace=0.1)
        plt.tight_layout()
        model_name = "Ensemble_NIDS"
        file_name = os.path.join('/app/results/', f"{model_name}_{self.dataset}_{self.protocol}_{self.class_type}_roc.pdf")
        fig.savefig(file_name, dpi=300, bbox_inches='tight', pad_inches=0.05)
        print(f"Multiclass ROC Curves for {model_name} Saved at {file_name}")
        plt.close()

    def plot_multiclass_confusion_matrix_vote(self, flow_model, payload_model, X_flow, X_payload, y, encoder, flow_scale=0.5, payload_scale=0.5):
        font_size = 16
        font_style = 'italic'
        print(f"Plotting multiclass confusion matrix for Vote_based_model ...")
        fig, ax = plt.subplots(figsize=(10, 7))
        y_pred = self.predict_vote_multiclass(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)
        y_test_original = encoder.inverse_transform(y)
        y_pred_original = encoder.inverse_transform(y_pred)
        y_test_numeric = encoder.transform(y_test_original)
        y_pred_numeric = encoder.transform(y_pred_original)
        cm = confusion_matrix(y_test_numeric, y_pred_numeric)
        if self.protocol=='tcp':
            codes = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J'] # Create a list of alphabets for tick labels
        elif self.protocol=='udp':
            codes = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'] # Create a list of alphabets for tick labels
        else:
            print("Unknown protocol. Exiting.")
        label_legend = [(alpha, label) for alpha, label in zip(codes, encoder.classes_)]
        display_labels = [alpha for alpha, _ in label_legend]
        cm_display = ConfusionMatrixDisplay(cm, display_labels=display_labels)
        cm_display.plot(cmap='Blues', ax=ax) # cmap='binary', cmap='viridis', cmap='cividis', cmap='plasma', cmap='inferno'
        handles = [plt.Line2D([0], [0], linestyle='', label=f"{num} - {label}") for num, label in label_legend]
        ax.legend(handles=handles, bbox_to_anchor=(0.5, -0.2), loc='lower center', ncol=4, frameon=False, fontsize=font_size-6)
        ax.get_images()[0].colorbar.remove() # Hides heatmap legend for the confusion matrix
        ax.spines.right.set_visible(True)
        ax.spines.top.set_visible(True)
        ax.tick_params(axis='both', which='both', labelsize=font_size-6, pad=3, color='black')
        ax.set_aspect('equal', adjustable='box')
        ax.set_xlabel(r'\textbf{Predicted Traffic Class}', 
                    fontsize=font_size-4, fontweight='bold', fontstyle=font_style, labelpad=4)
        ax.set_ylabel(r'\textbf{True Traffic Class}', 
                    fontsize=font_size-4, fontweight='bold', fontstyle=font_style, labelpad=4)
        ax.grid(False)
        plt.subplots_adjust(wspace=0.1, hspace=0.3)
        plt.tight_layout()
        model_name = "Ensemble_NIDS"
        file_name = os.path.join('/app/results/', f"{model_name}_{self.dataset}_{self.protocol}_{self.class_type}_confusion_matrix.pdf")
        fig.savefig(file_name, dpi=300,
                    bbox_inches='tight', pad_inches=0.05)
        print(f"Confusion Matrix for {model_name} saved at {file_name}")
        plt.close()

    def calculate_muticlass_fpr_vote(self, cm, name, encoder):
        num_classes = cm.shape[0]
        fpr_dict = {}
        for i in range(num_classes):
            positive_class = i # Select the positive class
            fp = np.sum(cm[:, positive_class]) - cm[positive_class, positive_class] # Extract the relevant values from the confusion matrix
            tn = np.sum(cm) - np.sum(cm[positive_class, :]) - np.sum(cm[:, positive_class]) + cm[positive_class, positive_class]
            fpr = fp / (fp + tn) # Calculate false positive rate
            fpr_dict[encoder.classes_[i]] = fpr  # Store FPR for the class # fpr_dict[i] = fpr # Store FPR for the class
        fpr_df = pd.DataFrame.from_dict(fpr_dict, orient='index', columns=['FPR']) # Save the FPR values to a CSV file
        fpr_df.index.name = 'Class'
        name = "Ensemble_NIDS"
        file_name = os.path.join('/app/results/', f"{name}_{self.dataset}_{self.protocol}_{self.class_type}_fpr.csv")
        fpr_df.to_csv(file_name)
        print(f"Multiclass FPR for {name} saved at {file_name}")
        return fpr_dict
    
    def get_multiclass_fpr_vote(self, flow_model, payload_model, X_flow, X_payload, y, encoder, flow_scale=0.5, payload_scale=0.5):
        y_class_labels =  encoder.classes_
        y_pred = self.predict_vote_multiclass(flow_model, payload_model, X_flow, X_payload, flow_scale, payload_scale)
        cm = confusion_matrix(y, y_pred) # encoder.transform(y_pred))
        model_name = "Ensemble_NIDS"
        fpr_results = self.calculate_muticlass_fpr_vote(cm, model_name, encoder)
        for class_idx, fpr in fpr_results.items():
            print(f"Class {class_idx}: FPR = {fpr}")  
        print(f"{model_name} Class Names: ", y_class_labels)