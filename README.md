# MITREMapper
MITREMapper is an intelligent threat analysis platform designed to automate the extraction and mapping of Tactics, Techniques, and Procedures (TTPs) from observed behaviors of threat actors. By leveraging Large Language Models, MITREMapper efficiently deciphers complex threat data and aligns it with the MITRE ATT&amp;CK framework.

## Installation
- Clone this repository using: `git clone https://github.com/Dineshkriss/MitreMapper.git`
- Create a Python virtual environment using: `python -m venv venv`
- Activate the virtual environment using: `.\venv\Scripts\Activate.ps1` (On Windows) and `source venv/bin/activate` (On Linux)
- Install the required dependencies using: `pip install -r requirements.txt`
- Run the application using: `python app.py`
- Go to `http://localhost:5000` on any web browser.

Note: If you have an NVIDIA GPU use: `pip install torch --index-url https://download.pytorch.org/whl/cu118` to install Pytorch with CUDA support, and then continue from `pip install -r requirements.txt`

To update the MITRE ATT&amp;CK matrices, run:
- `python update.py --all` = Update all matrices.
- `python update.py --matrix [enterprise,mobile,ics]` = Updates one specified matrix.

## Hardware Requirements
To run this locally, your system should atleast have 6GBs of VRAM and 16GBs of RAM.
