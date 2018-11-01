import os
import logging
import json

class InfernoManager():
    
    # TO-DO:
    # Take inferno level as parameter to aid naming conventions
    # Replace hardcoded hash strings by enum

    def __init__(self, filename, level_num):
        self.dir = os.path.dirname(__file__)
        self.level_num = level_num
        # Load json from the file
        self.level = self.__load_level(filename)
        self.hashes = {
            'sha1':[],
            'pbk':[],
            'sha512':[],
            'argon':[]
        }
        # Populate the above array by separating hashes
        self.__separate_hashes()
        self.__print_hashes_info()

    # PRIVATE BLOCK
    def __load_level(self, filename):
        # Try to open the file
        filepath = os.path.join(self.dir, filename)
        with open(filepath) as f:
            try:
                data = json.load(f)
            except FileNotFoundException as e:
                logging.exception(e)
                raise
        
        return data
    
    def __separate_hashes(self):
        hashes_from_file = self.get_hashes()
        for hash in hashes_from_file:
            hash_type = ''
            if '$sha1$' in hash:
                hash_type = 'sha1'
            elif '$pbkdf2' in hash:
                hash_type = 'pbk'
            elif '$6$' in hash:
                hash_type = 'sha512'
            elif '$argon2i$' in hash:
                hash_type = 'argon'
            
            self.hashes[hash_type].append(hash)
    
    def __print_hashes_info(self):
        len_sha1 = len(self.hashes['sha1'])
        len_pbk = len(self.hashes['pbk'])
        len_sha512 = len(self.hashes['sha512'])
        len_argon = len(self.hashes['argon'])
        len_total = len_sha1 + len_pbk + len_sha512 + len_argon
        
        print('LEVEL %i' % self.level_num)
        print('Total hashes: %i' % len_total)
        print('sha1: %i' % len_sha1)
        print('pbk: %i' % len_pbk)
        print('sha512: %i' % len_sha512)
        print('argon: %i' % len_argon)

    # PUBLIC BLOCK
    # In this function be careful with naming conventions
    def export_hashes_to_files(self):
        new_folder = 'hashes_' + str(self.level_num)
        new_dir = os.path.join(self.dir,new_folder)
        
        # create folder
        if not os.path.exists(new_dir):
            os.makedirs(new_dir)
        
        hash_types = ['sha1','pbk','sha512','argon']
        for hash_type in hash_types:
            hash_array = self.hashes[hash_type]
            filename = hash_type + '_' + str(self.level_num) + '.hashes'
            filepath = os.path.join(new_dir,filename)
            with open(filepath,'w') as f:
                for item in hash_array:
                    f.write("%s\n" % item)

    # Getters
    def get_ciphertext(self):
        return self.level['ciphertext']

    def get_hashes(self):
        return self.level['hashes']

    def get_shares(self):
        return self.level['shares']
