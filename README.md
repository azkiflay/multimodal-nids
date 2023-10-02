# NIDSENSEMBLE
NIDSENSEMBLE is Network Intrusion Detection Systems (NIDS) that leverages complementary threat intelligence by learning from flow-based traffic features, and the first few bytes of a prototocl payload. It is composed of two separate Machine Learning (ML) models each of which are trained on distinct types of network data. To detect network intrusions, NIDSENSEMBLE combines classification probabilities from the two ML models using a soft voting scheme to detect attacks. It extracting and labeling packet capture (PCAP) files of modern network intrusion detection system datasets. Most previous NIDSes are based on flow-based features and their detection capability of payload-based attacks is limited. Furthermore, flow-based NIDSes are limited in their adpatability to different network environments due to inherent changes in network traffic characteristics. NIDSENSEMBLE tackles these challenges by learning from both flow-based and payload-based traffic features in a complementary manner.

# Installation
Step 1: Download CSV files and Packet Capture (PCAP) files of the UNSW-NB15 IDS dataset
    A) Download the UNSW-NB15 CSV files from https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys?path=%2F
    $ mkdir data
    $ cd data
    $ mkdir unsw_nb15_dataset
    $ mv /path/to/UNSW-NB15-CSV-FILES/* ./unsw_nb15_dataset/

    B) Download PCAP files of the UNSW-NB15 IDS dataset from https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys?path=%2FUNSW-NB15%20-%20pcap%20files/
    $ mkdir feb_pcap
    $ mv /path/to/pcaps 17-2-2015/* ./feb_pcap # UNSW-NB15 PCAPs in February
    $ $ mkdir jan_pcap
    $ mv /path/to/pcaps 22-1-2015/* ./jan_pcap  # UNSW-NB15 PCAPs in January
Note that at the time of writing this document, the CSV and PCAP files of the UNSW-NB15 dataset are available at the above URLs. If the URLs of the files change, they are to be downloaded from the new URLs according to announcements by the authors of the UNSW-NB15 IDS dataset or their affiliated institution.

Step 2: Install Docker Engine on Ubuntu
Installation using the Apt repository. Before you install Docker Engine for the first time on a new host machine, you need to set up the Docker repository. Afterwards, you can install and update Docker from the repository. More details at https://docs.docker.com/engine/install/ubuntu/
A) Set up Docker's Apt repository.
Add Docker's official GPG key:
$ sudo apt-get update
$ sudo apt-get install ca-certificates curl gnupg
$ sudo install -m 0755 -d /etc/apt/keyrings
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

Add the repository to Apt sources:
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

B) Install the Docker packages.
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

C) Verify that the Docker Engine installation is successful by running the hello-world image.
The following command downloads a test image and runs it in a container. When the container runs, it prints a confirmation message and exits.
$ sudo docker run hello-world
You have now successfully installed and started Docker Engine.

# Usuage
Step 3: Change to project directory
Open terminal
$ cd nidsensemble
$ mkdir results
$ docker compose build
$ docker compose up postgres
Open another terminal tab (Ctrl + Shift + T)
$ docker compose up nidsensemble # on the new terminal tab

The PosgreSQL database will be stored on docker_data subdirectory, which is on the same directory as the nidsensemble project directory.
The container and other associated files are also stored in the docker_data subdirectory.

$ sudo apt install nvidia-cuda-toolkit # On Host machine (not outsided Docker container) NVIDIA GPU Drivers for Tensorflow

Finally, ensure that no other application is using port number 5432, which is needed to run postgresql database. If port 5432 is in use, unused port can be setup for nidsensemble in the docker-compose.yaml.
