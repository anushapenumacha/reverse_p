import yara
import os

class yara_parse:
    def __init__(self, out_list):
        self.out_list = out_list
        self.rules = None
        self.matches = {}

    def rules_compile(self, folder_path):
        compiled = {}
        rule_files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
        for f in rule_files:
            compiled[f] = os.path.join(folder_path, f)
        self.rules = yara.compile(filepaths=compiled)

    def rules_match(self):
        _tstring = ""
        for _dat in self.out_list:
            _tstring += _dat
        self.matches =self.rules.match(data = _tstring)

    def display_output(self):
        keywords = []
        yara_list = []
        data = ""
        data += ("******************************************************\n")
        data += ("**************** YARA OUTPUT**************************\n")
        for key in self.matches.keys():
            data += ("Description: {}\n".format(self.matches[key][0]["meta"]["Description"]))
            for str1 in self.matches[key][0]["strings"]:
                keywords.append(str1["data"])
            keywords = list(set(keywords))
        for key in keywords:
            data += ("Keyword found : {}\n".format(key))
        for word in self.out_list:
            if any([key in word for key in keywords]):
                yara_list.append(word)
        data += ("******************************************************\n")
        data += ("**************** LOGS FOUND***************************\n")
        for _dat in yara_list:
            data += (_dat)
            data += "\n"
        data += ("******************************************************")
        y_file = open("yara_output.log","w")
        y_file.write(data)
        y_file.close()
        print("YARA output has been written to yara_output.log")




