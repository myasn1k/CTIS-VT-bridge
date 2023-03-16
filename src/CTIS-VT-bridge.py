import logging
import traceback
from config import Config
from ctis import CTIS
from vt import VT
import re
import sys

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y/%m/%d %H:%M:%S",
    handlers=[
        logging.StreamHandler()
    ]
)

def sync_matches(vt, ctis):
    vt_matches = vt.get_matches()
    logging.info(f"Matches found: {len(vt_matches)}")
    for match in vt_matches:
        logging.info(f"Adding match with ID {match['context_attributes']['notification_id']} for ruleset {match['context_attributes']['ruleset_name']} and rule {match['context_attributes']['rule_name']} to CTIS")
        ctis.add_match(match)
        logging.info(f"Removing match with ID {match['context_attributes']['notification_id']} for ruleset {match['context_attributes']['ruleset_name']} and rule {match['context_attributes']['rule_name']} from VT")
        vt.del_match(match["context_attributes"]["notification_id"])

def sync_rulesets(vt, ctis):
    vt_rulesets = vt.get_all_rulesets()
    ctis_rulesets = ctis.get_all_rulesets()

    logging.info(f"VT rulesets: {len(vt_rulesets)}")
    logging.info(f"CTIS rulesets: {len(ctis_rulesets)}")

    for cid, crset in ctis_rulesets.items():
        if crset["is_monitored"]:
            if not crset["VT_id"]:
                logging.info(f"Pushing ruleset {crset['name']} to VT")
                crset["VT_id"] = vt.add_ruleset(crset)
                ctis.add_vt_id_as_alias(crset["VT_id"], cid)
            else:
                for crule in crset["rules"]:
                    if crule["rule"] not in vt_rulesets[crset["VT_id"]]["rules"]:
                        logging.info(f"Adding rule {crule['name']} to ruleset {crset['name']} on VT")
                        vt_rulesets[crset["VT_id"]]["rules"] += "\n" + crule["rule"]
                vt_rules = vt_rulesets[crset["VT_id"]]["rules"].split("\n")    
                updated = ""
                for vrule in vt_rules:
                    found = False
                    for crule in crset["rules"]:
                        if crule["rule"] in vrule:
                            found = True
                            updated += vrule + "\n"
                    if not found and vrule:
                        logging.info(f"Removing rule {vrule.split()[1]} from ruleset {crset['name']} on VT")
                if updated != vt_rulesets[crset["VT_id"]]["rules"]:
                    vt.update_rules(crset["VT_id"], updated)
        else:
            if crset["VT_id"] and crset["VT_id"] in vt_rulesets.keys():
                logging.info(f"Removing {crset['name']} from VT")
                vt.remove_ruleset(crset["VT_id"])
                ctis.remove_vt_id_as_alias(crset["VT_id"], cid)

def main(argv):
    vt = VT(url="https://www.virustotal.com", apikey=Config["vt"]["key"])
    ctis = CTIS(Config["ctis"]["url"], Config["ctis"]["user"], Config["ctis"]["pass"],
            Config["ctis"]["ruleset_indicator_name"], Config["ctis"]["rule_indicator_name"],
            Config["ctis"]["monitoring_src"])
    sync_matches(vt, ctis)
    sync_rulesets(vt, ctis)
    logging.info("Finished")

if __name__ == "__main__":
    try:
        main(sys.argv)
    except:
        logging.error(f"Got a fatal error")
        logging.error(traceback.format_exc().strip())
