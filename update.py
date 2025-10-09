import requests
import json
import os
import argparse


def get_stix_enterprise():
    os.makedirs("attack-matrices", exist_ok=True)

    # Download and save latest Enterprise MITRE ATT&CK® data
    stix_enterprise = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json").json()
    with open("./attack-matrices/enterprise-attack.json", "w") as f:
        json.dump(stix_enterprise, f)
    print("Enterprise ATT&CK matrix data downloaded and saved successfully as ./attack-matrices/enterprise-attack.json ✅")


def get_stix_mobile():
    os.makedirs("attack-matrices", exist_ok=True)

    # Download and save latest Mobile MITRE ATT&CK® data
    stix_mobile = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json").json()
    with open("./attack-matrices/mobile-attack.json", "w") as f:
        json.dump(stix_mobile, f)
    print("Mobile ATT&CK matrix data downloaded and saved successfully as ./attack-matrices/mobile-attack.json ✅")


def get_stix_ics():
    os.makedirs("attack-matrices", exist_ok=True)

    # Download and save latest ICS MITRE ATT&CK® data
    stix_ics = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json").json()
    with open("./attack-matrices/ics-attack.json", "w") as f:
        json.dump(stix_ics, f)
    print("ICS ATT&CK matrix data downloaded and saved successfully as ./attack-matrices/ics-attack.json ✅")


def get_stix_all():

    os.makedirs("attack-matrices", exist_ok=True)

    # Download and save latest MITRE ATT&CK® data
    stix_enterprise = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json").json()
    with open("./attack-matrices/enterprise-attack.json", "w") as f:
        json.dump(stix_enterprise, f)
    print("Enterprise ATT&CK matrix data downloaded and saved successfully as ./attack-matrices/enterprise-attack.json ✅")
    
    stix_mobile = requests.get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json").json()
    with open("./attack-matrices/mobile-attack.json", "w") as f:
        json.dump(stix_mobile, f)
    print("Mobile ATT&CK matrix data downloaded and saved successfully as ./attack-matrices/mobile-attack.json ✅")
    
    stix_ics = requests.get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json").json()
    with open("./attack-matrices/ics-attack.json", "w") as f:
        json.dump(stix_ics, f)
    print("ICS ATT&CK matrix data downloaded and saved successfully as ./attack-matrices/ics-attack.json ✅")


def main():
    parser = argparse.ArgumentParser(description="Download MITRE ATT&CK matrix data")
    
    # Create mutually exclusive group for --all and --matrix options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true",
                       help="Download and save all latest matrices from MITRE ATT&CK")
    group.add_argument("--matrix", choices=["enterprise", "mobile", "ics"],
                      help="Download and save a specific MITRE ATT&CK matrix")
    
    args = parser.parse_args()
    
    if args.all:
        get_stix_all()
    elif args.matrix == "enterprise":
        get_stix_enterprise()
    elif args.matrix == "mobile":
        get_stix_mobile()
    elif args.matrix == "ics":
        get_stix_ics()


if __name__ == '__main__':
    main()