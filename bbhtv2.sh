#!/bin/bash

# Color Variables
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)

AMASS_VERSION=3.8.2

# Banner
echo "${RED} ######################################################### ${RESET}"
echo "${RED} #                 TOOLS FOR BUG BOUNTY                  # ${RESET}"
echo "${RED} ######################################################### ${RESET}"

# Function to display logo
logo() {
    echo "${BLUE}
                ___ ___ _  _ _____     ___
               | _ ) _ ) || |_   _|_ _|_  )
               | _ \ _ \ __ | | | \ V // /
               |___/___/_||_| |_|  \_//___| ${RESET}"
}
logo

echo ""
echo "${GREEN} Tools created by the best people in the InfoSec Community ${RESET}"
echo "${GREEN}                   Thanks to everyone!                     ${RESET}"
echo ""

# Update & install dependencies
echo "${GREEN} [+] Updating and installing dependencies ${RESET}"
echo ""

sudo apt-get -y update && sudo apt-get -y upgrade

sudo add-apt-repository -y ppa:apt-fast/stable < /dev/null
echo "debconf apt-fast/maxdownloads string 16" | sudo debconf-set-selections
echo "debconf apt-fast/dlflag boolean true" | sudo debconf-set-selections
echo "debconf apt-fast/aptmanager string apt-get" | sudo debconf-set-selections
sudo apt install -y apt-fast

# Install necessary packages
sudo apt-fast install -y apt-transport-https libcurl4-openssl-dev libssl-dev jq ruby-full \
libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev \
libffi-dev python3-dev python3-setuptools libldns-dev python3-pip python3-dnspython git \
npm nmap phantomjs gem perl parallel
pip3 install jsbeautifier

echo ""
echo ""

# Set shell aliases
echo "${GREEN} [+] Setting bash_profile aliases ${RESET}"
curl -s https://raw.githubusercontent.com/unethicalnoob/aliases/master/bashprofile > ~/.bash_profile
echo "${BLUE} If it doesn't work, set it manually ${RESET}"
echo ""

# Install Golang
echo "${GREEN} [+] Installing Golang ${RESET}"
if [ ! -f /usr/bin/go ]; then
    cd ~
    wget -q -O - https://raw.githubusercontent.com/canha/golang-tools-install-script/master/goinstall.sh | bash
    echo 'export GOROOT=$HOME/.go' >> ~/.bash_profile
    echo 'export GOPATH=$HOME/go' >> ~/.bash_profile
    echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile
    source ~/.bash_profile
else
    echo "${BLUE} Golang is already installed${RESET}"
fi
echo ""
echo "${BLUE} Done Install Golang ${RESET}"
echo ""

# Function to check for a command, and install if not found
check_command() {
    command -v "$1" >/dev/null 2>&1 || { echo "${BLUE}Installing $1...${RESET}"; eval "$2"; }
}

# Clone or pull a git repository
clone_or_pull() {
    if [ -d "$2" ]; then
        echo "${BLUE}Updating $1...${RESET}"
        cd "$2" && git pull
    else
        echo "${BLUE}Cloning $1...${RESET}"
        git clone "$3" "$2"
    fi
}

# Install tools using go and GitHub
install_go_tools() {
    tools=(
        "github.com/OJ/gobuster"
        "github.com/bp0lr/gauplus"
        "github.com/lc/gau"
        "github.com/projectdiscovery/subfinder"
        "github.com/projectdiscovery/chaos-client"
        "github.com/projectdiscovery/tldfinder"
        "github.com/projectdiscovery/notify"
        "github.com/projectdiscovery/mapcidr"
        "github.com/projectdiscovery/shuffledns"
        "github.com/projectdiscovery/asnmap"
        "github.com/projectdiscovery/uncover"
        "github.com/projectdiscovery/cdncheck"
        "github.com/projectdiscovery/pdtm"
        "github.com/projectdiscovery/katana"
        "github.com/projectdiscovery/httpx"
        "github.com/projectdiscovery/alterx"
        "github.com/projectdiscovery/dnsx"
        "github.com/gwen001/github-subdomains"
        "github.com/ffuf/ffuf"
        "github.com/michenriksen/aquatone"
        "github.com/haccer/subjack"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu"
        "github.com/Tanmay-N/CORS-Scanner"
        "github.com/j3ssie/metabigor"
        "github.com/harleo/knockknock"
    )
    for tool in "${tools[@]}"; do
        go install -v "$tool"@latest
    done
}

# Install basic tools
echo "${GREEN}#### Installing Basic Tools ####${RESET}"
clone_or_pull "altdns" "$HOME/tools/knockpy" "https://github.com/guelfoweb/knock.git"
cd ~/tools/knockpy
sudo python3 setup.py install

clone_or_pull "asnlookup" "$HOME/tools/asnlookup" "https://github.com/yassineaboukir/asnlookup.git"
cd ~/tools/asnlookup
sudo pip3 install -r requirements.txt

# Install fuzzing tools
echo "${GREEN}#### Installing Fuzzing Tools ####${RESET}"
install_go_tools

# Dirsearch
clone_or_pull "dirsearch" "$HOME/tools/dirsearch" "https://github.com/maurosoria/dirsearch.git"

# Wfuzz
sudo apt-fast install -y wfuzz

# Installing domain enumeration tools
echo "${GREEN}#### Installing Domain Enum Tools ####${RESET}"
clone_or_pull "SubDomainizer" "$HOME/tools/SubDomainizer" "https://github.com/nsonaniya2010/SubDomainizer.git"
cd ~/tools/SubDomainizer && chmod +x SubDomainizer.py
sudo pip3 install -r requirements.txt

clone_or_pull "domain_analyzer" "$HOME/tools/domain_analyzer" "https://github.com/eldraco/domain_analyzer.git"

clone_or_pull "massdns" "$HOME/tools/massdns" "https://github.com/blechschmidt/massdns.git"
cd ~/tools/massdns && make

clone_or_pull "sub.sh" "$HOME/tools/subsh" "https://github.com/cihanmehmet/sub.sh.git"
cd ~/tools/subsh && chmod +x sub.sh

# CORS Tools
echo "${GREEN}#### Installing CORS Tools ####${RESET}"
clone_or_pull "corsy" "$HOME/tools/corsy" "https://github.com/s0md3v/Corsy.git"
cd ~/tools/corsy && sudo pip3 install -r requirements.txt

clone_or_pull "CORScanner" "$HOME/tools/corscanner" "https://github.com/chenjj/CORScanner.git"
cd ~/tools/corscanner && sudo pip3 install -r requirements.txt

echo "${GREEN}#### Installing CMS Tools ####${RESET}"
clone_or_pull "CMSmap" "$HOME/tools/CMS/CMSmap" "https://github.com/Dionach/CMSmap.git"
cd ~/tools/CMS/CMSmap && sudo pip3 install .

clone_or_pull "wig" "$HOME/tools/CMS/wig" "https://github.com/jekyc/wig.git"
cd ~/tools/CMS/wig && sudo python3 setup.py install

echo "${GREEN}#### Downloading Wordlists ####${RESET}"
clone_or_pull "SecLists" "$HOME/tools/Wordlists/SecLists" "https://github.com/danielmiessler/SecLists.git"
