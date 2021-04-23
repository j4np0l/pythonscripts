import re
import argparse

#Looks for a regex on a file
#To look for @domain.com emails on a text that have them either starting with a space or a comma: [^ |,][\w.\w]+@domain.com

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--file','-f', help='File to find the regex')
    parser.add_argument('--regex','-r', help='Regular Expression')

    args = parser.parse_args()

    pattern = re.compile(args.regex)
    #We create an empty set, a set is a list that can't contain duplicates
    results = set()

    for i, line in enumerate(open(args.file)):
        for match in re.findall(pattern, line):
            results.add(match) #We add each result to the set

    for j in results:
        print(j)
    
