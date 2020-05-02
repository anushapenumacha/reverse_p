import csv
import re

class Filter:
    def __init__(self):
        self.all_data = list()
        self.out_data = list()
        self.pml_data = list()
        self.filtered_list = list()

    def parse_file(self, input_file):
        _file = open(input_file, newline='')
        _file_data =csv.reader(_file)
        for _fd in _file_data:
            if len(_fd) != 7:
                continue
            self.pml_data.append(_fd)

    def get_proc_events(self):
        for _dat in self.pml_data:
            if _dat[3] in ['Process Create'] and _dat[5] == 'SUCCESS':
                _add_data = {}
                _add_data["type"] = "Process Created"
                _add_data["pname"] = _dat[1]
                _add_data["ppid"] = _dat[2]
                _add_data["cmd_line"] = _dat[6].split("line: ")[1]
                _add_data["pid"] = _dat[6].split("PID: ")[1].split(',')[0]
                _out = "[{}]:[{}]{}-->{}[{}]".format(_add_data["type"],  _add_data["ppid"], _add_data["pname"],
                                                   _add_data["cmd_line"],  _add_data["pid"])
                if _out not in self.out_data:
                    self.out_data.append(_out)
                self.all_data.append(_add_data)
            if _dat[3] in ['Process Exit'] and _dat[5] == 'SUCCESS':
                _add_data = {}
                _add_data["type"] = "Process Exit"
                _add_data["pname"] = _dat[1]
                _add_data["pid"] = _dat[2]
                _out = "[{}]:[{}]{}--".format( _add_data["type"], _add_data["pid"],_add_data["pname"])
                if _out not in self.out_data:
                    self.out_data.append(_out)
                self.all_data.append(_add_data)

    def get_file_events(self):
        for _dat in self.pml_data:
            _found = False
            _add_data = {}
            if _dat[3] in ['IRP_MJ_CREATE'] and _dat[6].split(',')[-1].strip() == "OpenResult: Created":
                _add_data["type"] = "File Create"
                _found = True
            if _dat[3] in ['IRP_MJ_SET_INFORMATION'] and _dat[6].split(',')[-1].strip() == "Delete: True":
                _add_data["type"] = "File Delete"
                _found = True
            if _found == True:
                _add_data["fname"] = _dat[4]
                _add_data["pid"] = _dat[2]
                _add_data["pname"] = _dat[1]
                _out = "[{}]:[{}]{}-->{}".format(_add_data["type"],  _add_data["pid"], _add_data["pname"], _add_data["fname"])
                if _out not in self.out_data:
                    self.out_data.append(_out)
                self.all_data.append(_add_data)

    def get_registry_events(self):
        for _dat in self.pml_data:
            _add_data = {}
            _found = False
            if _dat[3] in ['RegCreateKey'] and _dat[5] == 'SUCCESS':
                _add_data["type"] = "Reg CreateKey"
                _found = True
            if _dat[3] in ['RegSetValue'] and _dat[5] == 'SUCCESS':
                _add_data["type"] = "Reg SetVal"
                _found = True
                if "Data" in _dat[6]:
                    _add_data["val"] = _dat[6].split("Data: ")[-1]
                else:
                    _add_data["val"] = ""
            if _dat[3] in ['RegDeleteKey']:
                _add_data["type"] = "Reg DeleteKey"
                _found = True
            if _dat[3] in ['RegDeleteValue']:
                _add_data["type"] = "Reg DeleteVal"
                _found = True
            if _found == True:
                _add_data["kname"] = _dat[4]
                _add_data["pid"] = _dat[2]
                _add_data["pname"] = _dat[1]
                _out = "[{}]:[{}]{}-->{}\n".format(_add_data["type"],  _add_data["pid"], _add_data["pname"], _add_data["kname"])
                if "val" in _add_data.keys():
                    _out += "[data-->{}]".format(_add_data["val"])
                #Limit to only run key registry events [ Detect persistence ]
                if _out not in self.out_data:
                    self.out_data.append(_out)
                self.all_data.append(_add_data)

    def get_network_events(self):
        for _dat in self.pml_data:
                if 'TCP '  in _dat[3] and _dat[5] == 'SUCCESS':
                    _add_data = {}
                    _add_data["pname"] = _dat[1]
                    _add_data["pid"] = _dat[2]
                    _add_data["conn"] = _dat[4]
                    _add_data["type"] = _dat[3]
                    _out = "[{}]:[{}]{}-->{}".format(_add_data["type"],  _add_data["pid"], _add_data["pname"], _add_data["conn"])
                    if _out not in self.out_data:
                        self.out_data.append(_out)
                    self.all_data.append(_add_data)

    def get_all_events(self):
        self.get_proc_events()
        self.get_file_events()
        self.get_registry_events()
        self.get_network_events()
        return self.out_data

    def filter(self, pid_list, pname_list, mapping):
        for _val in self.out_data:
            if mapping == True:
                match = re.search(r'\[([0-9]{3,})\]', _val)
                match1 = re.search('\[([0-9]{{3,}})\]{pname}-->'.format(pname=pname_list[0]), _val)
                match2 = re.search(r'{pname}\[([0-9]{{3,}})\]'.format(pname=pname_list[0]), _val)
                if pid_list[0] == match.group(1) and (match1 != None or match2 != None):
                    self.filtered_list.append(_val)
            else:
                if pid_list != None:
                    match = re.search(r'\[([0-9]{3,})\]',_val)
                    if match.group(1) in pid_list:
                        self.filtered_list.append(_val)
                if pname_list != None:
                    match = any([re.search('\[([0-9]{{3,}})\]{pname}--'.format(pname=pname.lower()), _val.lower()) != None for pname in pname_list])
                    match1 = any([re.search(r'{pname}\[([0-9]{{3,}})\]'.format(pname=pname.lower()), _val.lower()) != None for pname in pname_list])
                    if match or match1:
                        self.filtered_list.append(_val)
        return self.filtered_list
