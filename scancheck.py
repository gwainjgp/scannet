#!/usr/bin/env python3

# -*- coding: utf-8 -*
#
# Este script prueba las funciones de analisis que se vayan añadiendo
#



import argparse,json,io
from flask import jsonify

from config import * # cargo config como absoluto

#Procesamos los argumentos
parser = argparse.ArgumentParser(description='Probando las opciones de analisis')
parser.add_argument('command',help='comando, list to get all posibilities', default='nothing')
parser.add_argument('scanfile', help='Enrich scan file to analize')
parser.add_argument('-r','--referencefile', help='Enrich scan file to compare')
parser.add_argument('-c','--configfile', help='Configurations options',default='config.json')

args = parser.parse_args()

command = args.command
command = command.lower()
configFile = args.configfile

# Importamos lo que sabemos hace
import checklib
from checklib import *
checkActions = checklib.__all__

# Cargamos la configuración
conf = config(configFile)

if (command == 'list' ):
    print ('Estos son los check se se pueden hacer:')
    for i in checkActions:
        print ('  *  Name: ',i, ', description: "',eval(i).getDescription(), '", re expresion: ',eval(i).getRE())

else:
    print ('# Se solicita probar el comando: ', command)
    if (command in checkActions):
        scanData = load_json(args.scanfile)
        print ('# Probando:' + command)
        if eval(command).getReference():
            referenceData = load_json(args.referencefile)
            if args.referencefile:
                resultCommand = eval(command).getMade(scanData,referenceData)
            else:
                resultCommand = 'Este comando requiere fichero de referencia y no la ha indicado'              
        else:
            resultCommand = eval(command).getMade(scanData)
        print ('# Resultado:')
        print(json.dumps(resultCommand, indent=4, sort_keys=True))

    else:
        print ('Error, no se conoce el comando: ' + command)
