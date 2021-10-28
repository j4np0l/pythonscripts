import re
import argparse
import os

#Looks for a regex on a file or on files within a Dir
#To look for @domain.com emails on a text that have them either starting with a space or a comma: [^ |,][\w.\w]+@domain.com

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--file','-f', help='File to find the regex',required=False)
    parser.add_argument('--dir','-d', help='Dir to find the regex in',required=False)
    parser.add_argument('--regex','-r', help='Regular Expression',required=True)

    args = parser.parse_args()

    pattern = re.compile(args.regex)

    if args.file is not None:
        for i, line in enumerate(open(args.file)):
            for match in re.findall(pattern, line):
                print("line "+str(i)+": "+line)
    elif args.dir is not None:
        for root, dirs, files in os.walk(args.dir):
            for file in files:
                fullpath = os.path.join(root, file)
                for i, line in enumerate(open(fullpath)):
                    for match in re.findall(pattern, line):
                        print("Match on "+fullpath+":"+str(i))
                        print(line)
    else:
        print("Need to specify a Dir or File")
        exit()
