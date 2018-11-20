# Access Policies




# Tenant Policies

The tenant_policies directory includes the scripts that helps automating the provisioning of a tenant.


## bd_and_epg.py 

This script provisions application profiles, EPG's and BD's according to a csv file (see bd_and_epg.csv). It links as well EPG's to contracts.

BD's without subnet are provisioned as following:
* Unicast routing disabled
* Unknown unicast set to flood
* ARP flooding enabled

BD's with subnet are provisioned af following:
* Unicast routing enable
* Unknown unicast set to hardware proxy
* ARP flooding disabled

The script doesnt modify a BD’s or EPG’s that already exist
The script doesnt create VRFs neither the contracts. So if not created upfront , VRF’s and contracts resolution (in BD’s and EPG’s) will fail (missing-target).

```
bd_and_epg.py --help
usage: bd_and_epg.py [-h] [-c CONFIG_FILE] [-s URL] [-u USERNAME]
                     [-p PASSWORD]

optional arguments:
  -h, --help      show this help message and exit
  -c CONFIG_FILE  csv config file
  -s URL          APIC URL
  -u USERNAME     Username to login to APIC
  -p PASSWORD     Password to login to APIC
  
bd_and_epg.py -c bd_and_epg.csv -u admin -p password -s https://apic1  
```




# Multipod
