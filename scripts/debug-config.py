import sys
import pdb
from akanda.router.models import Configuration

if __name__ == '__main__':
    # Simple script that helps debug faulty configurations
    with open(sys.argv[1], 'r') as c:
        try:
            conf = Configuration(conf_dict=eval(c.read()))
            print conf
            print '-' * 80
            print conf.validate()
            print '-' * 80
            print conf.pf_config
        except Exception as e:
            pdb.set_trace()
