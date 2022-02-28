from rainbow_m4 import *
import signal


def handler(signum,frame):
    raise Exception('Timeout')
    
if __name__ == '__main__':
    ctx = np.random.randint(0,256,(48,),np.uint8).tobytes()
    e, rng_out = prng_gen(ctx,skip=False)
    with open(RNG_DUMP, 'a') as f:
        f.write(f'skip_address,rng_out_skip,match\n')
        f.write(f'0x00, {rng_out}, False\n')

    skip_address = e.functions['randombytes_with_state'] - 1

    signal.signal(signal.SIGALRM, handler)
    timeout=20
    signal.alarm(timeout)
    while(skip_address < e.functions['prng_set']):
        match = False
        try:
            _, rng_out_skip = prng_gen(skip=True,e=e,skip_address=skip_address)
            if(rng_out_skip == rng_out):
                print(f'Found match for skip at {skip_address}: rng_out: {rng_out}, rng_out_skip: {rng_out_skip}')
                match = True
            with open(RNG_DUMP, 'a') as f:
                f.write(f'{hex(skip_address)},{rng_out_skip},{match}\n')
        except Exception as ex:
            print('Skipping 0x%x raised exception'%skip_address)
            print(ex)
        finally:
            try:
                d = e.disassemble_single(skip_address, 4)
            except Exception as e:
                print('Couldnt disassemble instruction at 0x%'%sk_address)
                print('Retrying with instruction length 2')
                d = e.disassemble_single(skip_address, 4)
            skip_address += d[1]
