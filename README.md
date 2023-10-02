# NIDSENSEMBLE
NIDSENSEMBLE is Network Intrusion Detection Systems (NIDS) that leverages complementary threat intelligence by learning from flow-based traffic features, and the first few bytes of a prototocl payload. It is composed of two separate Machine Learning (ML) models each of which are trained on distinct types of network data. NIDSENSEMBLE combines classification probabilities from the two ML models using a soft voting scheme to detect attacks. Most previous ML-based NIDSes are based on flow-based features and they have limited ability to detect payload-based attacks. Furthermore, flow-based NIDSes are limited in their adpatability to different network environments due to inherent changes in network traffic characteristics and due to the fact that flow-based data features are collected in specific scenarios. NIDSENSEMBLE tackles these challenges by learning from both flow-based and payload-based traffic features in a complementary manner. NIDSENSEMBLE has been trained and tested using Comma Separated Values (CSV) values, and the corresponding Packet Capture (PCAP) files of the publicly available UNSW-NB15 dataset.

# Dataset
### Download the Comma Separated Values (CSV) files of the UNSW-NB15 dataset from [here](https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys?path=%2FUNSW-NB15%20-%20CSV%20Files).
  ```bash
  mkdir data
  cd data
  mkdir unsw_nb15_dataset
  mv /path/to/UNSW-NB15-CSV-FILES/* ./unsw_nb15_dataset/
  ```

### Download Packet Capture (PCAP) files of the UNSW-NB15 dataset from [here](https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys?path=%2FUNSW-NB15%20-%20pcap%20files/).
  ```bash
  mkdir feb_pcap
  mv /path/to/pcaps 17-2-2015/* ./feb_pcap # UNSW-NB15 PCAPs in February
  mkdir jan_pcap
  mv /path/to/pcaps 22-1-2015/* ./jan_pcap  # UNSW-NB15 PCAPs in January
  ```
**Notes**
+ At the time of writing this document, the CSV and PCAP files of the UNSW-NB15 dataset are available at the above URLs. If the URLs of the files change, they are to be downloaded from the new URLs according to announcements by the authors of the UNSW-NB15 IDS dataset or their affiliated institution.
+ The PCAP files of the dataset are nearly **100 Gigabyte**. So, it is important to make sure enough disk storage is avaialbe for the PCAP and CSV files of the UNSW-NB15 dataset as well as free disk space to install the required packages for the project.

# Installation
## Install Docker Engine on Ubuntu
Installation using the Apt repository. Before you install Docker Engine for the first time on a new host machine, you need to set up the Docker repository. Afterwards, you can install and update Docker from the repository. More details at https://docs.docker.com/engine/install/ubuntu/
### Set up Docker's Apt repository.
Add Docker's official GPG key:
  ```bash
  sudo apt-get update
  sudo apt-get install ca-certificates curl gnupg
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  ```
Add the repository to Apt sources:
  ```bash
  echo \
    "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update
  ```

### Install the Docker packages.
  ```bash
  sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  ```

### Verify that the Docker Engine installation is successful by running the hello-world image.
The following command downloads a test image and runs it in a container.
  ```bash
  sudo docker run hello-world
  ```
When the container runs, it should print a confirmation message. If so, you have now successfully installed and started Docker Engine.
### Install NVIDIA GPU Drivers for Tensorflow on host machine
  ```bash
  sudo apt install nvidia-cuda-toolkit
  ```
# Usuage
Open terminal and run the project using the following commands.
  ```bash
  cd nidsensemble
  mkdir results
  docker compose build
  docker compose up postgres
  ```

Note that the PosgreSQL database will be stored on docker_data subdirectory, which is on the same directory as the nidsensemble project directory. The container and other associated files are also stored in the docker_data subdirectory.

Finally, ensure that no other application is using port number 5432, which is needed to run postgresql database. If port 5432 is in use, unused port can be setup for nidsensemble in the docker-compose.yaml.

To run NIDSENSEMBLE, open another terminal tab (Ctrl + Shift + T) and use the following command to run the project.
  ```bash
  docker compose up nidsensemble # on the new terminal tab
  ```
 NIDSENSEMBLE has two ML subsystems, a flow-based susbsytem and a payload-based subsystem, which are trained using flow-based traffic features and the first 32 bytes of protocol payload, respectively. Separate ML models are trained for Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) of the UNSW-NB15 dataset. Note that TCP and UDP constitute more than 97% of total traffic flows in the dataset. The trained ML models as well as the model evaluation results are saved in the *results* subdirectory.
# Citation
If you would like to use NIDSENSEMBLE in your work, please cite our paper which presents details of how NIDSENSEMBLE works and the obtained results:
```bash
Paper Bibtex
```
