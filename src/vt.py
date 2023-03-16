import requests

class VT():

    headers = {}
    url = ""

    def __init__(self, url: str, apikey: str):
        self.url = url
        self.headers = {"x-apikey": apikey, "accept": "application/json", "content-type": "application/json"}

    def do_patch(self, url, json):
        return requests.patch(self.url + url, headers=self.headers, json=json).status_code

    def do_delete(self, url):
        return requests.delete(self.url + url, headers=self.headers).status_code

    def do_get(self, url):
        return requests.get(self.url + url, headers=self.headers).json()
    
    def do_post(self, url, json):
        return requests.post(self.url + url, headers=self.headers, json=json).json()

    def update_rules(self, id, rules):
        json = {
                  "data": {
                        "type": "hunting_ruleset",
                        "attributes": {
                            "rules": rules
                        }
                  }
               }
        return True if self.do_patch(f"/api/v3/intelligence/hunting_rulesets/{id}", json) == 200 else False

    def del_match(self, id):
        return True if self.do_delete(f"/api/v3/intelligence/hunting_notifications/{id}") == 200 else False

    def get_matches(self):
        tmp = self.do_get("/api/v3/intelligence/hunting_notification_files?limit=40&count_limit=10000")
        matches = tmp["data"]
        while tmp["meta"]["count"] == 100 and "cursor" in tmp["meta"].keys():
            tmp = self.do_get("/api/v3/intelligence/hunting_notification_files?limit=40&cursor="+tmp["meta"]["cursor"]+"&count_limit=10000")
            matches.append(tmp["data"])
        return matches

    def get_all_rulesets(self):
        tmp_rulesets = self.do_get("/api/v3/intelligence/hunting_rulesets")["data"]
        rulesets = {}
        for rset in tmp_rulesets:
            rulesets[rset["id"]] = {"name": rset["attributes"]["name"], "rules": rset["attributes"]["rules"]}
        return rulesets

    def add_ruleset(self, ruleset):
        rules = ""
        for rule in ruleset["rules"]:
            rules += rule["rule"] + "\n"
        json = {
                  "data": {
                          "type": "hunting_ruleset",
                          "attributes": {
                                        "name": ruleset["name"],
                                        "enabled": True,
                                        "rules": rules,
                                        }
                          }
               }
        return self.do_post("/api/v3/intelligence/hunting_rulesets", json)["data"]["id"]

    def remove_ruleset(self, id):
        return True if self.do_delete(f"/api/v3/intelligence/hunting_rulesets/{id}") == 200 else False
