import difflib
import re
class diff_data:
    def __init__(self, data1, data2):
        self.data1 = data1
        self.data2 = data2

    def get_diff(self):
        self.data1 = [re.sub(r'\[([0-9]{3,})\]', '', i) for i in self.data1]
        self.data2 = [re.sub(r'\[([0-9]{3,})\]', '', i) for i in self.data2]
        d = difflib.HtmlDiff()
        result = d.make_file(self.data1, self.data2)
        result = result.replace('td nowrap="nowrap"', 'td')
        with open("test.html", 'w') as f:
            f.writelines(result)
        print("Your output has been written to test.html in the same directory")