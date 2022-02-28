#!/usr/bin/python
import psycopg2 as psql
import numpy as np
import sys
import copy
import logging
import os
from pathlib import Path
sys.path.append('src')
from arg_parser import load_config
from datetime import datetime

TIMESTAMP = datetime.utcnow().strftime("%Y_%m_%d__%H_%M_%S")

class Connector():
    conn = None 
    table: str
    config: dict
    logger: logging.Logger
    def __init__(self):
        config = load_config(__class__.__name__) # returns connector, i.e. not subclass type
        self.logger = get_logger(f'{__name__}:{type(self).__name__}')
        try:
            self.config = copy.deepcopy(config)
            del self.config['password']
            self.conn = psql.connect(**config)
            if self.conn is None:
                self.logger.error('No connection established')
                sys.exit()
            self.logger.info(f'Connector for table initialized with {self.config}')
           
        except (psql.DatabaseError) as error:
            self.logger.error(error)
            if self.conn is not None:
                self.conn.close()
                sys.exit()
    
    def create_table(self):
        if  self.query_single(f"SELECT to_regclass('{self.table}')")[0] is None:
            self.logger.info(f'Creating table {self.table}...')
            self.execute(open(self.config['database_file'], 'r').read())
        else:
            self.logger.info(f'Table {self.table} already exists')

    def query_single(self, query='') -> str:
        with self.conn.cursor() as cur:
            cur.execute(query)
            return cur.fetchone()
    
    def query(self, query='') -> list:
         with self.conn.cursor() as cur:
            cur.execute(query)
            return cur.fetchall()

    def execute(self, command='') -> None:
        with self.conn.cursor() as cur:
            try:
                cur.execute(command)
                self.conn.commit()
            except (psql.DatabaseError) as error:
                print(error)
                self.conn.rollback()
        
    def close(self):
        if self.conn:
            print('Closing database')
            self.conn.close()

class ProfileConnector(Connector):
    def __init__(self):
        super().__init__()
        config = load_config(type(self).__name__) 
        self.table = config['table']
        self.config.update(config)
        self.create_table()
    
    def store_row(self, row) -> None:
        with self.conn.cursor() as cur:  
            try:
                cur.execute(f"""
                            INSERT INTO {self.table} (m, sm, v, v_address, inst_skip)
                            VALUES (%(m)s, %(sm)s, %(v)s, %(v_address)s, %(inst_skip)s);
                            """,
                            row
                )
                self.conn.commit()
            except (psql.DatabaseError) as error:
                print('ERROR', error)
                self.conn.rollback()

    def store_rows(self, rows):
        for row in rows:
            self.store_row(row)
    
    def fetch_rows(self,subquery='') -> list:
        resp = self.query(
                    f"""
                    SELECT * from {self.table} {subquery}
                    """
                    
                    )
        rows = [
                {
                    'm': row[0],
                    'sm': row[1],
                    'v': row[2],
                    'v_address': row[3],
                    'inst_skip': row[4],
                }
                for row in resp]
        return rows

class Logger():
    name: str
    local_path: str
    local_logger: logging.Logger
    write: dict
    level: str

    def __init__(self,name):
        config = load_config(type(self).__name__)
        self.name = name 
        try:
            self.write = {
                            'local': config['write_local'] == 'True',
                            'remote': config['write_remote'] == 'True'
            }
            self.logger = logging.getLogger(self.name)
            self.config = copy.deepcopy(config)
            del self.config['password']
            self.table = config['log_table']
            self.level = config['remote_log_level']
            for key in copy.deepcopy(list(config.keys())):
                if key not in ['host','port','database','user','password']:
                    del config[key]
            self.conn = psql.connect(**config)
            if self.conn is None:
                self.logger.error('No connection established')
                sys.exit()
            self.logger.info(f'Remote logger initialized with {self.config}')
           
        except (psql.DatabaseError) as error:
            self.logger.error(error)
            if self.conn is not None:
                self.conn.close()
                sys.exit()

    def store_log(self, message, level) -> None:
        if logging._nameToLevel[level] < logging._nameToLevel[self.level]:
            return
       
        log = {
            'message': str(message),
            'name': self.name,
            'timestamp': TIMESTAMP,
            'level': level

        }
        with self.conn.cursor() as cur:  
            try:
                cur.execute(f"""
                            INSERT INTO {self.table} (name, message, timestamp, level)
                            VALUES (%(name)s, %(message)s, %(timestamp)s, %(level)s);
                            """,
                            log
                )
                self.conn.commit()
            except (psql.DatabaseError) as e:
                self.logger.error(e)
                self.conn.rollback()

    def create_table(self):
        if  self.query_single(f"SELECT to_regclass('{self.table}')")[0] is None:
            self.logger.info(f'Creating table {self.table}...')
            self.execute(open(self.config['database_file'], 'r').read())
        else:
            self.logger.info(f'Table {self.table} already exists')

    def query_single(self, query='') -> str:
        with self.conn.cursor() as cur:
            cur.execute(query)
            return cur.fetchone()
    
    def query(self, query='') -> list:
         with self.conn.cursor() as cur:
            cur.execute(query)
            return cur.fetchall()

    def execute(self, command='') -> None:
        with self.conn.cursor() as cur:
            try:
                cur.execute(command)
                self.conn.commit()
            except (psql.DatabaseError) as error:
                print(error)
                self.conn.rollback()
        
    def close(self):
        if self.conn:
            print('Closing database')
            self.conn.close()

    def warning(self, message):
        if self.write['remote']:
            self.store_log(message, level='WARNING')
        if self.write['local']:
            self.logger.warning(message)
    
    def error(self, message):
        if self.write['remote']:
            self.store_log(message, level='ERROR')
        if self.write['local']:
            self.logger.error(message)

    def exception(self, message):
        if self.write['remote']:
            self.store_log(message, level='ERROR')
        if self.write['local']:
            self.logger.exception(message)
        
    def critical(self, message):
        if self.write['remote']:
            self.store_log(message, level='CRITICAL')
        if self.write['local']:
            self.logger.critical(message)
    
    def info(self, message):
        if self.write['remote']:
            self.store_log(message, level='INFO')
        if self.write['local']:
            self.logger.info(message)

    def debug(self, message):
        if self.write['remote']:
            self.store_log(message, level='DEBUG')
        if self.write['local']:
            self.logger.debug(message)


config = load_config('Logger') 
log_dir = config['local_log_dir']
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_levels={
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'debug': logging.DEBUG
}

logging.basicConfig(level=log_levels[config['local_log_level']])     
                
def get_logger(name):
    return Logger(name)


if __name__ == '__main__':
    con = Logger('test')
    con.create_table()
    con.info('Test')
    print(con.config)
    con.close()