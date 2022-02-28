import subprocess
from pathlib import Path
import re
from rainbow.generics import rainbow_arm
from unicorn.arm_const import *
from unicorn.unicorn_const import UC_HOOK_CODE
import numpy as np
import time
import pickle
import os

import SQL.connection

SK_FILE = 'sk_file'
PK_FILE = 'pk_file'
SEED_FILE = 'seed'
SEED_BYTES = 32


RAINBOW_REF_WD = Path('rainbow-submission-round2/Reference_Implementation')
PROJ_DIR = Path('.')
RAINBOW_BIN = PROJ_DIR/'elf/rainbow.elf'
VINEGARS_FILE = PROJ_DIR/'files/vinegars.bin'

PK_BYTES = 161600
SK_BYTES = 103648
SEED_BYTES = 32
BUF = 32 # have some space between mem regions
M_BYTES = 32
S_BYTES = 66
SM_BYTES = M_BYTES + S_BYTES
SIZE_T_BYTES = 8
BSS_START = 0x00026a60
BSS_SIZE = 0x00040d38
N_VINEGARS = 36
VIN_NBYTES = 18  # f16 representation -> two elements per byte
INT32_BYTES = 4
GET_VIN_ADDRESS = 0x0df94  # where to read vinegar address out of register
CORRECT_BYTES = 32
DIGEST_CK_BYTES = 32

sk_seed_address = BSS_START
pk_seed_address = sk_seed_address + SEED_BYTES + BUF
pk_address = pk_seed_address + SEED_BYTES + BUF
sk_address = pk_address + PK_BYTES + BUF
m_address = sk_address + SK_BYTES + BUF
sm_address = m_address + M_BYTES + BUF
smlen_address = sm_address + SM_BYTES + BUF
mlen_address = smlen_address + SIZE_T_BYTES + BUF



STACK_ADDR = 0xb0000000
STACK = (STACK_ADDR - BSS_SIZE, STACK_ADDR + 32)  #  we need a stack big enough to fit SK, PK and some more variables needed during crypto_sign_keypair

VIN_ADDR = 0x0000
GOT_VIN = False

def hook_code(mu, address, size, user_data):
    global VIN_ADDR, GOT_VIN
    if address == GET_VIN_ADDRESS and not GOT_VIN: # when randombytes is finished, read vinegars, 
        VIN_ADDR = mu.reg_read(UC_ARM_REG_R1)
        # print('Vinegars are at 0x%x'%VIN_ADDR)
        GOT_VIN = True


class drainbow:
    sk: bytes
    pk: bytes
    e: rainbow_arm
    skip_address: int = 0
    timeout: int
    skip: bool
    vinegars: bytes = None
    logger = SQL.connection.Logger
    connector = SQL.connection.ProfileConnector

    def __init__(self) -> None:
        self.logger = SQL.connection.get_logger(type(self).__name__)
        self.connector = SQL.connection.ProfileConnector()
        self.build_source()
        self.e = rainbow_arm(sca_mode=True)
        self.enable_vfp()
        self.e.load(RAINBOW_BIN.as_posix(), typ=".elf")
        self.e.STACK = STACK
        self.e.setup(sca_mode=self.e.sca_mode)
        self.skip = False
        self.e.emu.hook_add(UC_HOOK_CODE, hook_code)
      
    def build_source(self):
        cmd = [
                'make',
                '-f',
                f'{PROJ_DIR/"Makefile"}',
                'build'
            ]
        self.execute_cmd(cmd, log_msg='Building source binaries')

    def disassemble_source(self):
        cmd = [
                'make',
                '-f',
                f'{PROJ_DIR/"Makefile"}',
                'disassemble'
            ]
       
        self.execute_cmd(cmd,log_msg='Disassembling binaries')


    def clean_source(self):
        cmd = [
                'make',
                '-f',
                f'{PROJ_DIR/"Makefile"}',
                'clean'
            ]
        self.execute_cmd(cmd,log_msg='Cleaning binaries')

    def gen_keypair(self,seed:str = ''):  # generate keypair from reference implementation locally to save time
        seed = np.random.randint(0,256,(SEED_BYTES,),np.uint8).tobytes()
        cmd = [
                'make',
               f'PROJ_DIR=Ia_Classic' # for now only Ia_Classic supported
              ]

        self.execute_cmd(cmd, cwd=RAINBOW_REF_WD, log_msg='Generating keypair binaries')  # compile binaries according to variant
        cmd = [
                './rainbow-genkey',
                PK_FILE,
                SK_FILE
                # SEED_FILE # TODO: seed file is not being read correctly yet
                ]
        with open(RAINBOW_REF_WD/SEED_FILE, 'wb') as seed_file:
            seed_file.write(seed)
        self.execute_cmd(cmd,cwd=RAINBOW_REF_WD, log_msg='Generating keypair')
        
    def execute_cmd(self,system_command, log_msg, **kwargs):
        if log_msg:
            self.logger.info(log_msg)
        self.logger.info(f'system_command: {system_command}')
        popen = subprocess.Popen(
            system_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            **kwargs)
        for stdout_line in iter(popen.stdout.readline, ""):
            line = stdout_line.strip()
            if len(line) > 0:
                self.logger.debug(line)
        popen.stdout.close()
        return_code = popen.wait()
        if return_code:
            raise subprocess.CalledProcessError(return_code, system_command)

    def load_pk(self):
        self.logger.info('Loading private key')
        with open(RAINBOW_REF_WD/PK_FILE, 'r') as f:
            pk = f.read()
        pk = pk[re.search('\s=\s', pk).span()[1]:]  # clean out preamble
        pk = bytes.fromhex(pk)
        self.pk = pk
        self.e[pk_address] = pk
    
    def load_sk(self):
        self.logger.info('Loading secret key')
        with open(RAINBOW_REF_WD/SK_FILE, 'r') as f:
            sk = f.read()
        sk = sk[re.search('\s=\s', sk).span()[1]:]  # clean out preamble
        sk = bytes.fromhex(sk)  # convert to bytes
        self.sk = sk
        self.e[sk_address] = sk
    
    def load_keys(self):
        self.load_pk()
        self.load_sk()

    def enable_vfp(self):
        self.logger.info('Enabling vfp instructions')
        tmp=self.e.emu.reg_read(UC_ARM_REG_C1_C0_2)
        tmp = tmp | (0xf << 20)
        self.e.emu.reg_write(UC_ARM_REG_C1_C0_2,tmp)
        enable_vfp = 0x40000000
        self.e.emu.reg_write(UC_ARM_REG_FPEXC, enable_vfp)

    def place_fault(self, skip_address: int):
        self.logger.info(f'Injecting fault at {hex(skip_address)}')
        self.skip_address = skip_address
        self.skip = True
        
    def erase_fault(self):
        self.logger.info('Erasing fault')
        self.skip = False
        self.e.emu.hook_del(hook_code)

    def sign(self, m):
        self.logger.info(f'Signing message {m.hex()}')
        if not self.sk:
            self.logger.error('Load SK first!')
            exit()

        self.e[m_address] = m
        self.e[sm_address] = b'\x00' * SM_BYTES
        self.e[smlen_address] = b'\x00' * SIZE_T_BYTES

        self.e['r0'] = sm_address
        self.e['r1'] = smlen_address
        self.e['r2'] = m_address
        self.e['r3'] = M_BYTES
        self.e[self.e['sp']] = sk_address  # ARM calling convention : 4th+ parameter is on stack
        

        start = time.time()
        if self.skip:
            self.e.start(self.e.functions["crypto_sign"] | 1, self.skip_address)
            # y_addr = self.e['r0']
            # self.e.start(0x0e044|1 ,self.skip_address)
            # self.logger.info(f'y is {self.e[y_addr : y_addr + 32]}')
            d = self.e.disassemble_single(self.skip_address, 4)
            # self.e.print_asmline(self.skip_address, d[2], d[3])
            # print('\n')
            self.e.start(self.skip_address+d[1]|1,0)
            # self.logger.info(f'y is {self.e[y_addr : y_addr + 32]}')
            # self.e.start(0xe08c|1,0)
        else:
            self.e.start(self.e.functions["crypto_sign"] | 1, 0)
        
        if GOT_VIN:
            self.vin_address = VIN_ADDR
            vinegars = self.e[VIN_ADDR:VIN_ADDR+VIN_NBYTES]
            if self.vinegars is not None:
                vin_diff = np.frombuffer(vinegars, dtype=np.uint8) - np.frombuffer(self.vinegars, dtype=np.uint8)
                n_vin_fixed = len(vin_diff)-np.count_nonzero(vin_diff)
                self.logger.info(f'{n_vin_fixed*2}/{len(vin_diff)*2} vinegar variables were fixed') # factor 2 since two f16 variables are stored in a single byte
            self.vinegars = vinegars
            self.logger.info(f'Vinegars at {hex(VIN_ADDR)} are {self.vinegars.hex()}')
        end = time.time() - start
        self.logger.info(f'Finished crypto_sign after {end}s')
        ret_f = self.e['r0']
        if ret_f != 0:
            self.logger.error(f'Bad return value for crypto_sign: {ret_f}')
            exit()
        sm = bytes(self.e[sm_address:sm_address + SM_BYTES])
        self.logger.info(f'Signed message: {sm.hex()}')
        row = {
                'm': m,
                'sm': sm,
                'v': self.vinegars,
                'v_address': '0x%x'%VIN_ADDR,
                'inst_skip': '0x%x'%self.skip_address,
        }
        self.connector.store_row(row)
        return sm

    def verify(self, sm, m):  # m is actually not used but inferred from sm in the emulation
        self.logger.info(f'Verifying signed message {sm.hex()}')
        if not self.pk:
            self.logger.error('Load PK first!')
            exit()

        self.e[m_address] = m
        self.e[sm_address] = sm
        self.e[mlen_address] = b'\x00' * SIZE_T_BYTES

        self.e['r0'] = m_address
        self.e['r1'] = mlen_address
        self.e['r2'] = sm_address
        self.e['r3'] = SM_BYTES
        self.e[self.e['sp']] = pk_address

        start = time.time()
        self.e.start(self.e.functions["crypto_sign_open"] | 1, 0x0e420)
        digest_ck_address = self.e['r0']
        self.e.start(0x0e420 | 1, 0x0e444)
        correct_address = self.e['r0']
        self.e.start(0x0e444 | 1, 0)
        correct = bytes(self.e[correct_address:correct_address+CORRECT_BYTES])
        digest_ck = bytes(self.e[digest_ck_address:digest_ck_address+DIGEST_CK_BYTES])
        self.logger.info(f"Correct at {hex(correct_address)}: {correct}")
        self.logger.info(f"Digest at {hex(digest_ck_address)}: {digest_ck}")
        self.logger.info(f"Fault injection {'failed' if correct == digest_ck else 'succeeded'}")
        end = time.time() - start
        self.logger.info(f'Finished crypto_sign_open after {end}s')
        ret_f = self.e['r0']
        if ret_f != 0:
            self.logger.error(f'Signature did not verify correctly')
        else:
            self.logger.info('Signature verified correctly')

        return ret_f == 0, correct, digest_ck
    
    def store_vinegars(self):
        tmp = {
                'vinegars': self.vinegars,
                'address': self.vin_address,
            }
        self.logger.info(f'Storing vinegars {self.vinegars.hex()} at {hex(self.vin_address)}')
        try:
            with open(VINEGARS_FILE, 'wb') as f:
                pickle.dump(tmp, f)
        except Exception as e:
            self.logger.exception(e)
            exit()
        self.logger.debug('Successfully stored vinegars')
    
    def load_vinegars(self):  # we need those methods so that we can parallelize the whole thing
        self.logger.info('Loading vinegars')
        try:
            with open(VINEGARS_FILE, 'rb') as f:
                tmp = pickle.load(f)
                self.vinegars = tmp['vinegars']
                self.vin_address = tmp['address']
                self.e[self.vin_address] = bytes(self.vinegars)
        except Exception as e:
            self.logger.exception(e)
            exit()
        self.logger.debug(f'Successfully loaded vinegars {self.vinegars.hex()} at {hex(self.vin_address)}')



if __name__ == '__main__':
    # these adresses will change if C source code is modified and rebuilt
    # skip_address = 0xde2a ## for exiting loop
    # skip_address = 0xde20 ## for skipping memcpy
    skip_address = 0xdfb2 #  for skipping randombytes call

    ds = drainbow()
    ds.gen_keypair()
    ds.load_sk()
    m = np.random.randint(0,256,(np.random.randint(1,M_BYTES),),np.uint8).tobytes()
    sm = ds.sign(m)
    ds.store_vinegars()

    # del ds
    # ds = drainbow()
    ds.load_sk()
    ds.load_vinegars()
    ds.place_fault(skip_address=skip_address)
    sm_skip = ds.sign(m)

    



    dv = drainbow()
    dv.load_pk()
    verify_ok = dv.verify(sm, m)
    verify_ok_skip = dv.verify(sm_skip,m)
    verify_not_ok = dv.verify(np.random.randint(0,256,(np.random.randint(1,M_BYTES),),np.uint8).tobytes(), m)
    print(f'Verify ok for valid signature: {verify_ok}')
    print(f'Verify ok for skip signature: {verify_ok_skip}')
    print(f'Verify ok for invalid signature: {verify_not_ok}')