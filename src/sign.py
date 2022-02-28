from arg_parser import get_cmd_line_args
from drainbow import drainbow

if __name__ == '__main__':
    args = get_cmd_line_args()
    d = drainbow()
    if args['message']:
            with open(args['message'], 'r') as f:
                m = bytes.fromhex(f.read())
    else:
        print('Specify message to sign!')
        exit()

    if args['load_vinegars']:
        d.load_vinegars()
    if args['skip']:
        d.place_fault(skip_address=args['skip_address'])

    d.load_sk()
    sm = d.sign(m)

    if args['signed_message']:
        with open(args['signed_message'], 'w') as f:
            f.write(sm.hex())
    else:
        print('Specify path to save signed message')

    if args['store_vinegars']:
        d.store_vinegars()

    if args['signature_matrix']:
        with open(args['signature_matrix'], 'a') as f:
            f.write(f'{sm.hex()}\n')