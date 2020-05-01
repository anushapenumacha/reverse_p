from project.parser import Parser
from project.parse_data import Filter
from project.file_diff import diff_data
from project.yara_p import yara_parse

if __name__ == '__main__':
    filter = False
    args = Parser()
    args.argument_parser()
    parse_data = Filter()
    parse_data.parse_file(args.input_file)
    out1 = parse_data.get_all_events()

    out = open(args.output_file, "w")
    if args.pid != None or args.pname != None:
        filter = True
        f_list = parse_data.filter(args.pid, args.pname, args.mapping)
        print("Writing filtered output to - {}".format(args.output_file))
        out.write('\n'.join(f_list))
    else:
        print("Writing parsed output to {}".format(args.output_file))
        out.write('\n'.join(out1))
    out.close()

    if args.file_compare != None:
        new_data = Filter()
        new_data.parse_file(args.file_compare)
        out2 = new_data.get_all_events()
        if filter == True:
            f_list2 = new_data.filter(args.pid, args.pname, args.mapping)
            diff = diff_data(f_list, f_list2)
        else:
            diff = diff_data(out1, out2)
        diff.get_diff()

    if args.yara != None:
        yara_obj = yara_parse(out1)
        yara_obj.rules_compile(args.yara)
        yara_obj.rules_match()
        yara_obj.display_output()




