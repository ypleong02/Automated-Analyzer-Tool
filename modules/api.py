from modules.db import blackduck_cve, scantist_cve
from modules.db import get_cve
from modules.db import check_if_cve_exist
from modules.db import create_new_blackduck_cve
from modules.db import create_new_scantist_cve
from modules.db import get_all_cve_info


def get_rationale_cve_information(csv, format):
    
    result = []

    # read csv
    CVEs = csv

    # for loop to process each cve in csv
    for cve in CVEs:

        # check if cve exist
        exist = check_if_cve_exist(cve[0],cve[1])
        
        # if not exist -> create new cve
        if exist == 0:
            pass
            # create_cve(cve, format)
        
        # by default: exist -> Get rationale cve information
        rationale_cve = get_cve(cve[0],cve[1],format)

        # store in result list
        result.append(rationale_cve)
    
    # return result list
    return result


def create_cve(csv, tool):
    
    # read csv
    CVEs = csv

    for cve in CVEs:
        # pass in CVE information
        if tool == 1: # Blackduck
            create_new_blackduck_cve(cve)
        else:
            create_new_scantist_cve(cve)
            
        print("done")
    

def get_all_cve():
    cve = get_all_cve_info()
    return cve


if __name__ == "__main__":
    pass