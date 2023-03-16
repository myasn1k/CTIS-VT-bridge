import requests
import time
from datetime import datetime 
import urllib.parse

class CTIS():

    headers = {}
    url = ""
    ind_name_ruleset = ""
    ind_name_rule = ""
    src_mon = ""

    def __init__(self, url: str, username: str, password: str, ind_name_ruleset: str, ind_name_rule: str, src_mon: str):
        self.url = url
        self.src_mon = src_mon
        self.CTIS_login(username, password)
        self.ind_name_ruleset = ind_name_ruleset
        self.ind_name_rule = ind_name_rule

    def do_patch(self, url, etag, json):
        hdr = self.headers.copy()
        hdr["If-Match"] = etag
        return requests.patch(self.url + url, headers=hdr, json=json).json()

    def do_get(self, url):
        return requests.get(self.url + url, headers=self.headers).json()
    
    def do_post(self, url, json):
        return requests.post(self.url + url, headers=self.headers, json=json).json()

    def are_indicators_related(self, ind1, ind2):
        return ind1["_id"] in str(self.do_get(f"/indicators/relationships/indicators/{ind2['_id']}"))

    def add_match(self, match):
        rule = self.get_rule_by_name(match['context_attributes']['rule_name'])
        ruleset = self.get_ruleset_by_name(match['context_attributes']['ruleset_name'])
        if not self.are_indicators_related(rule, ruleset):
            raise Exception(f"Ruleset {match['context_attributes']['ruleset_name']} and rule {match['context_attributes']['rule_name']} aren't correlated")
        json = [
                  {
                    "vhash": match["attributes"].get("vhash", ""),
                    "submission_names": match["attributes"].get("names"),
                    "size": match["attributes"].get("size"),
                    "total": match["attributes"]["total_votes"]["harmless"]+match["attributes"]["total_votes"]["malicious"],
                    "harmless_votes": match["attributes"]["total_votes"]["harmless"],
                    "malicious_votes": match["attributes"]["total_votes"]["malicious"],
                    "sha256": match["attributes"]["sha256"],
                    "md5": match["attributes"]["md5"],
                    "sha1": match["attributes"]["sha1"],
                    "file-type": match["attributes"].get("detectiteasy", {}).get("filetype", ""),
                    "authentihash": match["attributes"].get("authentihash", ""),
                    "ssdeep": match["attributes"]["ssdeep"],
                    "community_reputation": match["attributes"]["reputation"],
                    "unique_sources": match["attributes"]["unique_sources"],
                    "first_seen": str(datetime.fromtimestamp(match["attributes"]["first_submission_date"])) + "Z",
                    "x-description": f"Yara snippet match: {match['context_attributes']['notification_snippet']}",
                    "x-sources": [
                        {
                            "source_name": "default",
                            "classification": 0,
                            "releasability": 0,
                            "tlp": 0
                        }
                    ]
                  }
               ]
        res = self.do_post("/x-files-metadata", json)
        if "_error" in res.keys() and res["_error"]["code"] == 409:
            return self.add_relationship("related-to", rule["_id"], "indicators", res["_error"]["message"]["_id"], "x-files-metadata")
        else:
            return self.add_relationship("related-to", rule["_id"], "indicators", res["_id"], "x-files-metadata")

    def add_relationship(self, rel_type, src, src_type, dst, dst_type):
        json_query = [
                {
                    "confidence": 100,
                    "relationship_type": rel_type,
                    "source_ref": src,
                    "source_type": src_type,
                    "target_ref": dst,
                    "target_type": dst_type,
                    "type": "relationship"
                }
            ]
        return self.do_post("/relationships", json_query)

    def add_vt_id_as_alias(self, vt_id, ctis_id):
        cur = self.do_get(f"/indicators/{ctis_id}")
        etag = cur["_etag"]
        cur["aliases"] = [ vt_id ]
        del cur["_aging_time"]
        del cur["_created"]
        del cur["_etag"]
        del cur["_links"]
        del cur["_response_datetime"]
        del cur["_updated"]
        return self.do_patch(f"/indicators/{ctis_id}", etag, cur)

    def remove_vt_id_as_alias(self, vt_id, ctis_id):
        cur = self.do_get(f"/indicators/{ctis_id}")
        etag = cur["_etag"]
        cur["aliases"] = []
        del cur["_aging_time"]
        del cur["_created"]
        del cur["_etag"]
        del cur["_links"]
        del cur["_response_datetime"]
        del cur["_updated"]
        return self.do_patch(f"/indicators/{ctis_id}", etag, cur)

    def get_ruleset_by_name(self, name):
        return self.do_get("/indicators?where="+urllib.parse.quote('{"name":"'+name+'","pattern_type":{"$in":["'+self.ind_name_ruleset+'"]}}')+"&page=1&max_results=25")["_items"][0]

    def get_rule_by_name(self, name):
        return self.do_get("/indicators?where="+urllib.parse.quote('{"name":"'+name+'","pattern_type":{"$in":["'+self.ind_name_rule+'"]}}')+"&page=1&max_results=25")["_items"][0]

    def get_all_rulesets(self):
        json = {
                 "where": {
                     "pattern_type": {
                         "$in": [
                             self.ind_name_ruleset
                         ]
                     }
                 }
            }

        rulesets = {}
        page_outer = 1
        while True:
            tmp_sets = self.do_post(f"/indicators/get?page={page_outer}&max_results=25", json)["_items"]
            if not tmp_sets:
                break
            for rset in tmp_sets:
                rules = []
                page_inner = 1
                while True:
                    tmp_rules = self.do_get("/indicators/relationships/indicators/" + rset['_id'] + f"?page={page_inner}&max_results=25")["_items"]
                    if not tmp_rules:
                        break
                    for rule in tmp_rules:
                        rules.append({"name": rule["name"], "is_monitored": True if self.src_mon in rule["x-sources"][0]["source_name"] else False, "rule": rule["pattern"].strip("\n")})
                    page_inner += 1
                rulesets[rset["_id"]] = {"name": rset["name"], "is_monitored": True if self.src_mon in str(rset["x-sources"]) else False, "VT_id": rset["aliases"][0] if "aliases" in rset.keys() and rset["aliases"] else "", "rules": rules}
            page_outer += 1

        return rulesets

    def CTIS_login(self, user, password):
        response = requests.get(f"{self.url}/login", auth=(user, password))
        self.headers = {'accept': 'application/json', 'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + response.json()["data"]["access_token"]}
