from drainbow import drainbow, M_BYTES
from arg_parser import get_cmd_line_args
import subprocess
from pathlib import Path
import warnings

import numpy as np

SCRIPTS_PATH = Path('src')
SIGN_PATH = SCRIPTS_PATH/'sign.py'
VERIFY_PATH = SCRIPTS_PATH/'verify.py'
KP_PATH = SCRIPTS_PATH/'keypair.py'
MAX_NUM_THREADS = 1


def verify(args,i,v):
    m_path = args["message"]+str(i)
    sm_path = args["signed_message"]+str(i)
    correct_path = args["correct"]+str(i)
    digest_ck_path = args["digest_ck"]+str(i)
    cmd = [
        'python',
        VERIFY_PATH,
        '-sm', sm_path,
        '-m', m_path,
        '--correct', correct_path,
        '--digest_ck', digest_ck_path
    ]
    if len(v) > 0:
        cmd += [v]

    return cmd


def sign_faulty(args,i,v):
    m = np.random.randint(0,256,(M_BYTES,),np.uint8).tobytes() # for simplicity, always have M_BYTES, could also random length (0,M_BYTES]
    m_path = args["message"]+str(i)
    sm_path = args["signed_message"]+str(i)
    with open(m_path, 'w') as f:  # individual message files
        f.write(m.hex())

    cmd = [
        'python',
        SIGN_PATH,
        '-m', m_path,
        '-sm', sm_path,
        '--skip_address', '0x%x'%args["skip_address"],
        '-s',
    ]
    if len(v) > 0:
        cmd += [v]
        
    return cmd

def keypair(args,v):
    cmd = [
        'python',
        KP_PATH
    ]

    if len(v) > 0:
        cmd += [v]

    return cmd

if __name__ == '__main__':
    args = get_cmd_line_args()

    if args['verbose_info']:
        v = '-v'
    elif args['verbose_debug']:
        v = '-vv'
    else:
        v = ''
    if args['keypair']:
        subprocess.run(keypair(args,v))

    j = 0
    c = 1
    while(c):
        if(j+MAX_NUM_THREADS <= args['n_signatures']):
            k = MAX_NUM_THREADS
        else:
            k = args['n_signatures'] - j
            c = 0
        print(f'Running threads {j}:{j+k}')
        processes = [subprocess.Popen(verify(args,i,v)) for i in np.arange(args['n_signatures'])[j:j+k]]
        for p in processes: p.wait()
        j += MAX_NUM_THREADS