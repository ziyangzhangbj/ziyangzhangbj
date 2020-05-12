"""
This scripts analyzes the illegal type0 hijack events sanitized with fiter-out siblings,DDos providers and pc relations. There are three functions described as follows:
filteringOut_by_Visibilit: filtering out the illegal events the visibility of which is lower than the specific threshold
group_illegalPOs_by_ValidOrigin_ASN: group illegal events by the hijacked origin AS and sort them by the number of hijacked prefixes reversely
group_illegalPOs_by_InvalidOrigin_ASN: group illegal events by the hijacking AS and sort them by the number of hijacking events

"""
import os
import pdb
import sys
import json
import gzip
import argparse
from collections import defaultdict


def filteringOut_by_Visibility(illegal_file,visibility_threshold)
    """
    Read and return the illegal detected events above a specific visibility value
    
    :param illegal_file: the path to the file with the all illegal detected events
    :type illegal_file: str
    :param visibility_threshold: a specific visibility value to filter out the illegal events
    :type visibility_threshold: int
    """
    
    f_out = gzip.open("results/filtered_{}".format(os.path.basename(illegal_file),"wt"))
    with gzip.open(illegal_file,"rt") as fin:
        for line in fin:
            record = json.loads(line.strip())
            filtered_illegal_invalids = list()
            for invalid in record["invalids"]:
                if not invalid["legit"]:
                    if invalid["full_peers_seeing"] >= visibility_threshold
                       filtered_illegal_invalids.append(invalid)
            record["invalids"] = filtered_illegal_invalids
            if len(filtered_illegal_invalids) > 0 and ':' not in record["roa_prefix"]:
               record["filtered_illegal_event_no"] = len(filtered_illegal_invalids)
               print(record)
               f_out.write("{}\n".format(json.dumps(record))
    f_out.close()
                          
def group_illegalPOs_by_ValidOrigin_ASN(filtered_illegal_file,date)
    
    d_datastore = dict()
    with gzip.open(filtered_illegal_file,"rt") as fin:
        for line in fin:
            record = json.loads(line.strip())
            for key in record["valid_origins"]
                 if key not in d_datastore:
                      d_datastore[key] = list()
                 d_datastore[key].append(（record["roa_prefix"],record["filtered_illegal_event_no"]))
                 
    l_datastore = list()
    for item in d_datastore:
        l_datastore.append( (item, d_datastore[item], len(d_datastore[item])) )
    l_datastore.sort(key=lambda tup: tup[2], reverse=True)    
    with open('results/' + date + '_group_illegalPOs_by_ValidOrigin_ASN.json', 'wt') as fp:
        json.dump(l_datastore, fp)
        
def group_illegalPOs_by_InvalidOrigin_ASN(filtered_illegal_file,date)
    
    d_datastore = dict()
    with gzip.open(filtered_illegal_file,"rt") as fin:
        for line in fin:
            record = json.loads(line.strip())
            for item in record["invalids"]
                 if item["invalid_origin"] not in d_datastore:
                      d_datastore[item["invalid_origin"]] = set()
                 d_datastore[item["invalid_origin"]].add(（record["roa_prefix"],record["valid"],item))
                 
    l_datastore = list()
    for item in d_datastore:
        l_datastore.append( (item, d_datastore[item], len(d_datastore[item])) )
    l_datastore.sort(key=lambda tup: tup[2], reverse=True)    
    with open('results/' + date + '_group_illegalPOs_by_InvalidOrigin_ASN.json', 'wt') as fp:
        json.dump(l_datastore, fp)
        
def main():
      arg_parser = argparse.ArgumentParser(description="This script takes as an input the json file with all illegal detected event entries. The output is two files.")          
      arg_parser.add_argument('-i', "--input_file", dest="input_file", type=str, help="The name of the input file. Format of the filename should by DATE 'DD_MM_YYY'", required=True)
      arg_parser.add_argument('-t', "--threshold_visibility", dest="visibility_threshold", type=float, default=0.0, help="The minimum of visibility to filter out illegal events. ")
      args = arg_parser.parse_args()
      illegal_file = args[0]
      if len(args)==1:
        visibility_threshold = 0.0
        print('The threshold of visibility is the default value(0.0)!')
      else if len(args)==2:
        print('The threshold of visibility is %f'%args[1])
        visibility_threshold = args[1]
      else :
        print('Too many arguments!')
        exit()
      date = '_'.join((illegal_file.split('/'))[1].split('_')[0:3])        
      filteringOut_by_Visibility(illegal_file,visibility_threshold)
      group_illegalPOs_by_ValidOrigin_ASN("results/filtered_{}".format(os.path.basename(illegal_file)),date)
      group_illegalPOs_by_InvalidOrigin_ASN("results/filtered_{}".format(os.path.basename(illegal_file)),date)
      
