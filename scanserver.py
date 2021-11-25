#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask
from flask import jsonify
import json

# Para trabajar con directorios
import glob
import os

# para cargar la configuración como parámetro
import argparse
#Procesamos los argumentos
parser = argparse.ArgumentParser(description='Servidor REST API de analisis')
parser.add_argument('-c','--configfile', help='Cofiguración en formato JSON', default='config.json')
args = parser.parse_args()
configFile = args.configfile

# Aux functions


def load_conf(fichero):
    with open(fichero) as File:
        try:
            config = {}
            config = json.load(File)
            File.close()
            return config
        except Exception as error:
            print ('Error al procesar el fichero json: ',fichero, 'error: ', error)

class config:
    configFile = configFile
    def __init__(self):
        self.config = load_conf(self.configFile)
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


## API

def create_app():
    app = Flask(__name__)
    return app

app = create_app()

#Que sabamos hacer
@app.route('/functions', methods=['GET'])
def get_functions():
    response = {'message': 'success'}
    return jsonify(response)

#Que redes podemos examinar
@app.route('/environment', methods=['GET'])
def get_environment():
    response = config['ipNetworks']
    return jsonify(response)

#Que ficheros se van a usar
@app.route('/scanfiles', methods=['GET'])
def get_scanfiles():
    response = { 'scanfile': conf.getScanFile(), 'referencefile' : conf.getReferenceFile() }
    return jsonify(response)    

if __name__ == '__main__':
    # Prepare the config
    #config = load_conf(configFile)
    #config['default'] = config['ipNetworks'][0]
    #config['referencefile'],config['scanfile'] = getWorkfiles(config['directory'] + '/' + config['default'] + '/' + config['filePattern'])
    conf = config()

    app.run(debug=True)