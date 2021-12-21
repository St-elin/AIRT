from stix2 import MemoryStore
import json
import os

class Converter:
    
    def APID_convertion(self, path_to_bundle: str):
        src = MemoryStore()
        src.load_from_file(path_to_bundle)

        with open('NewIncident.json') as fh:
            data = json.load(fh)
        incident_technique_ids = []
        for tech in data['techniques']:
            incident_technique_ids.append(tech['techniqueID'])
        return list(set(incident_technique_ids))
