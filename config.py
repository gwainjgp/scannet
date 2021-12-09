#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

# Para trabajar con directorios
import glob
import os

# Aux functions
def load_json(fichero):
    with open(fichero) as File:
        try:
            config = {}
            config = json.load(File)
            File.close()
            return config
        except Exception as error:
            print ('Error al procesar el fichero json: ',fichero, 'error: ', error)

class config:
    def __init__(self,configFile = 'config.json'):
        self.configFile = configFile
        self.config = load_json(self.configFile)
        self.config['default'] = self.config['ipNetworks'][0]

    def getRoute(self):
        return self.config['directory'] + '/' + self.config['default'] + '/' + self.config['filePattern']

    def getScanFile(self):
        list_of_files = glob.glob(self.getRoute()) # * menns all if need specific format then *.csv
        list_of_files.sort(key=os.path.getctime)
        return list_of_files[-1]
    def getReferenceFile(self):
        list_of_files = glob.glob(self.getRoute()) # * means all if need specific format then *.csv
        list_of_files.sort(key=os.path.getctime)
        return list_of_files[-2]

