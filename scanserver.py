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

# Load config
from config import * # cargo config como absoluto

## Funciones de análisis
# Importamos lo que sabemos hacer
import checklib
from checklib import *
checkActions = checklib.__all__



## API

def create_app():
    app = Flask(__name__)
    return app

app = create_app()

#Que sabamos hacer
@app.route('/functions', methods=['GET'])
def get_functions():
    response = []
    for i in checkActions:
        response.append({'name': i, 'description' : eval(i).getDescription(), 're': eval(i).getRE()})
    return jsonify(response)

#Que redes podemos examinar
@app.route('/environment', methods=['GET'])
def get_environment():
    response = { 'environments' : conf.config['ipNetworks'], 'default' : conf.config['default']}
    return jsonify(response)

#Cambiar el entorno
@app.route('/environment/<network>', methods=['GET'])
def set_environment(network):
    if network:
        if network in conf.config['ipNetworks']:
            conf.config['default'] = network    
    response = { 'environments' : conf.config['ipNetworks'], 'default' : conf.config['default']}
    return jsonify(response)

#Que ficheros se van a usar
@app.route('/files', methods=['GET'])
def get_files():
    response = { 'scanfile': conf.getScanFile(), 'referencefile' : conf.getReferenceFile() }
    return jsonify(response)    


# Haz cositas
@app.route('/doit/<command>', methods=['GET'])
def get_doit(command):
    response = {'name' : command  , 'environment' : conf.config['default']}
    if (command in checkActions):
        scanData = load_json(conf.getScanFile())
        response['scanfile'] = conf.getScanFile()
        print ('# Probando:' + command)
        if eval(command).getReference():
            referenceData = load_json(conf.getReferenceFile())
            response['referencefile'] = conf.getReferenceFile()
            #referenceData = load_json('../datos/redroja/enrich_scan-195.77.128.0_22-2021-10-15.json')
            #response['referencefile'] = '../datos/redroja/enrich_scan-195.77.128.0_22-2021-10-15.json'
            response.update(eval(command).getMade(scanData,referenceData))
        else:
            response.update(eval(command).getMade(scanData))
    else:
        response = { 'name' : 'command  ', 'result' : 'Command not found'}
    return jsonify(response)

if __name__ == '__main__':
    # Cargamos a configuración 
    conf = config()

    app.run(debug=True)