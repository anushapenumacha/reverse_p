import argparse

class Parser:
    def __init__(self):
        self.mapping = False
        self.pid = None
        self.pname = None
        self.input_file = None
        self.output_file = "output_data.log"
        self.file_compare = None
        self.yara = None

    def argument_parser(self):
        parser = argparse.ArgumentParser(description='Process procmon files')
        parser.add_argument('--file', help='Input file to process', required=True)
        parser.add_argument('--output', help='Output file', required=False)
        parser.add_argument('--compare', help='Add another file to get diff', required=False)
        filter_opts = parser.add_argument_group(title = "Filter by options")
        filter_opts.add_argument('--pid',nargs='+', help='Filter based on pid', required=False)
        filter_opts.add_argument('--pname',nargs='+', help='Filter based on process name', required=False)
        filter_opts.add_argument('--mapping', help='Map pid to its process name', action='store_true')
        parser.add_argument('--yara', help='Yara rule checker- Provide yara directory name', required=False)
        args = parser.parse_args()
        if args.file:
            self.input_file = args.file
        if args.output:
            self.output_file = args.output
        if args.compare:
            self.file_compare = args.compare
        if args.pid:
            self.pid = args.pid
        if args.pname:
            self.pname = args.pname
        if args.mapping:
            self.mapping = args.mapping
        if args.yara:
            self.yara = args.yara

    def print_args(self):
        print(self.input_file)
        print(self.output_file)



