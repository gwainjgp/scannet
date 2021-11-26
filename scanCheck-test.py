#!/usr/bin/env python3

# -*- coding: utf-8 -*
#
# Este script prueba las funciones de analisis que se vayan añadiendo
#



import argparse,json,io
from flask import jsonify

#Procesamos los argumentos
parser = argparse.ArgumentParser(description='Probando las opciones de analisis')
parser.add_argument('command',help='comando, list to get all posibilities', default='nothing')
parser.add_argument('scanfile', help='Enrich scan file to analize')
parser.add_argument('-r','--referencefile', help='Enrich scan file to compare')

args = parser.parse_args()

command = args.command
command = command.lower()

## Functions
def loadScan(fichero):
    with open(fichero) as savedDataFile:
        try:
            oldScanJson = {}
            oldScanJson = json.load(savedDataFile)
            savedDataFile.close()
            return oldScanJson
        except Exception as error:
            print ('Error al procesar el fichero json: ',fichero, 'error: ', error)
            
            
# Importamos lo que sabe hacer el cuñao
import checklib
from checklib import *
checkActions = checklib.__all__

if (command == 'list' ):
    print ('Estos son los check se se pueden hacer:')
    for i in checkActions:
        print ('  *  Name: ',i, ', description: "',eval(i).getDescription(), '", re expresion: ',eval(i).getRE())

else:
    print ('# Se solicita probar el comando: ', command)
    if (command in checkActions):
        scanData = loadScan(args.scanfile)
        print ('# Probando:' + command)
        if eval(command).getReference():
            referenceData = loadScan(args.referencefile)
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
