import argparse
from configparser import ConfigParser
from pathlib import Path
import re
import logging

def load_config(section):
        parser = ConfigParser()
        cmd_line_args = get_cmd_line_args() 
        parser.read(Path(cmd_line_args['config_path']))
        db = {}
        if parser.has_section(section):
            params = parser.items(section)
            for param in params:
                if param[0] in cmd_line_args.keys() and cmd_line_args[param[0]]:
                    param_val = cmd_line_args[param[0]]
                else:
                    param_val = param[1]
                if re.compile(r'\\|/').search(param_val):
                    db[param[0]] = Path(param_val)
                else:
                    db[param[0]] = param_val
        else:
            raise Exception('Section {0} not found in the {1} file'.format(section, cmd_line_args['config_path']))

        if 'password' in cmd_line_args.keys() and cmd_line_args['password']:
            db['password'] = cmd_line_args['password']
            if 'password_path' in db:
                 del db['password_path']
        elif 'password_path' in db and 'password' not in db:
            with open(Path(db['password_path'])) as pw_file:
                db['password'] = pw_file.read().strip()
                del db['password_path']
        if 'local_log_level' in db:
            if cmd_line_args['verbose_debug']:
                db['local_log_level'] = 'debug'
            if cmd_line_args['verbose_info']:
                db['local_log_level'] = 'info'
        return db

def get_cmd_line_args():
    parser = argparse.ArgumentParser(description='Fault Injection Analysis for Rainbow PQC Signature Scheme')
    parser.add_argument('-v', '--verbose_info', action='store_true', help='Set logger level to INFO')
    parser.add_argument('-vv', '--verbose_debug', action='store_true', help='Set logger level to DEBUG')
    parser.add_argument('-s','--skip',action='store_true', help='Inject fault')
    parser.add_argument('-kp','--keypair',action='store_true', help='Generate new keypair')
    parser.add_argument('--skip_address', metavar='skip_address', type=str, default='0x0df96', help='Specify address to skip execution')
    parser.add_argument('-lv','--load_vinegars', action='store_true', help='Load vinegars from previous emulation')
    parser.add_argument('-sv','--store_vinegars', action='store_true', help='Store vinegars')
    parser.add_argument('-c','--config_path', metavar='config path', type=str,
                        help='Path to postgres config file', default='files/config.ini')
    parser.add_argument('-m', '--message', metavar = 'message', type=str, default='m_sm/message', help='Path to message to sign')
    parser.add_argument('-sm', '--signed_message', metavar = 'signed_message',type=str, default = 'm_sm/signed_message',help='Path for signed message')
    parser.add_argument('-n', '--n_signatures', metavar='n_signatures',type=int, default=5, help='Number of signatures to collect')
    parser.add_argument('-ct', '--correct', metavar = 'correct', type=str, default='m_sm/correct', help='Path to correct variable from verification')
    parser.add_argument('-dig', '--digest_ck', metavar = 'digest_ck', type=str, default='m_sm/digest', help='Path to digest_ck variable from verification')
    parser.add_argument('-sign_mat', '--signature_matrix', metavar = 'signature_matrix', type=str, default='m_sm/signature_matrix', help='Row vector matrix for signatures for attack 1')
    parser.add_argument('-verify_mat', '--verification_matrix', metavar = 'verification_matrix', type=str, default='m_sm/verification_matrix', help='Row vector matrix for digest_ck and correct row vectors for attack 2')

    args =  vars(parser.parse_args())
    args['skip_address'] = int(args['skip_address'],16)
    return args