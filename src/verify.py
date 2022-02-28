from arg_parser import get_cmd_line_args
from drainbow import drainbow

if __name__ == '__main__':
    args = get_cmd_line_args()
    d = drainbow()

    
    if args['signed_message']:
            with open(args['signed_message'], 'r') as f:
                sm = bytes.fromhex(f.read())
    else:
        print('Specify path to signed message!')
        exit()

    if args['message']:
            with open(args['message'], 'r') as f:
                m = bytes.fromhex(f.read())
    else:
        print('Specify path to message!')
        exit()
    d.load_pk()
    verify_ok, correct, digest_ck = d.verify(sm,m)
    if args['correct']:
        with open(args['correct'], 'w') as f:
            f.write(correct.hex())
    if args['digest_ck']:
        with open(args['digest_ck'], 'w') as f:
            f.write(digest_ck.hex())

    if args['verification_matrix']:
        with open(args['verification_matrix'], 'a') as f:
            f.write(f'{correct.hex()}\n')
            f.write(f'{digest_ck.hex()}\n')