from arg_parser import get_cmd_line_args
from drainbow import drainbow

if __name__ == '__main__':
    args = get_cmd_line_args()
    d = drainbow()
    d.gen_keypair()
