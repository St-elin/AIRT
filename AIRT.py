import requests
import os
from stix2 import Filter, CompositeDataSource, FileSystemSource, TAXIICollectionSource, MemoryStore
from stix2.utils import get_type_from_id
# from taxii2client.v20 import Collection, Server
import re
import json
from itertools import chain


## Update-section

# refToTag = re.compile(r"ATT&CK-v(.*)")
# tags = requests.get("https://api.github.com/repos/mitre/cti/git/refs/tags").json()
# versions = list(map(lambda tag: refToTag.search(tag["ref"]).groups()[0] , filter(lambda tag: "ATT&CK-v" in tag["ref"], tags)))

# def get_data_from_version(domain, version):
#     """get the ATT&CK STIX data for the given version from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'."""
#     stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/{domain}/{domain}.json").json()
#     return MemoryStore(stix_data=stix_json["objects"])

# src = get_data_from_version("enterprise-attack", "5.2")

## Query section

sep = os.sep


def layer_convertion(path_to_layer: str, url=False):
        """
        Converts layer form navigator to simple techniques dict
        """
        if url:
            try:
                data = requests.get(path_to_layer).json()
            except Exception as e:
                return f"[*] Error!\nInvalid path to layer"
        else:
            with open(path_to_layer) as fh:
                data = json.load(fh)
        if 'techniques' in data.keys() and data['techniques']:
            ids = list(set([tech['techniqueID'] for tech in data['techniques']]))
        else:
            return f"[*] Error!\nInvalid path to layer"
        return ids


def convert_layer_data(ids: dict, src) -> dict:
    if isinstance(ids, str):
        return ids
    pattern_ids = {}
    try:
        for tech_id in ids:
            tmp = src.query([ 
                Filter("external_references.external_id", "=", tech_id), 
                Filter("type", "=", "attack-pattern")
            ])[0]
            pattern_ids[tmp.id] = tmp.name
    except Exception as e:
        return f"[*] Error!\n Invalid layer structure"
    return pattern_ids


def InitializeDatasource(DomainPath='', FSPath='', Url='', domain='', version='', officialrepo=True) -> CompositeDataSource:
    """
    Function to initialize STIX datasources. Available methods:
    - local file: e.g. enterprise-attack.json
    - local dir: e.g. /path/to/stix/dir/with/domain/file
    - taxii server address: e.g. 
    """
    
    if DomainPath:
        mem = MemoryStore()
        mem.load_from_file(DomainPath)
        return mem
    if FSPath:
        fs = FileSystemSource(FSPath)
        return fs
    if officialrepo:
        refToTag = re.compile(r"ATT&CK-v(.*)")
        tags = requests.get("https://api.github.com/repos/mitre/cti/git/refs/tags").json()
        versions = list(map(lambda tag: refToTag.search(tag["ref"]).groups()[0] , filter(lambda tag: "ATT&CK-v" in tag["ref"], tags)))
        if version in versions and domain in ['enterprise-attack', 'mobile-attack', 'ics-attack']:
            domain_data = requests.get(f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/{domain}/{domain}.json").json()
        else:
            try:
                default_version = versions[-1]
                default_domain = 'enterprise-attack'
                domain_data = requests.get(f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{default_version}/{default_domain}/{default_domain}.json").json()
            except:
                raise ValueError("Incorrect domain or version")
        gitmem = MemoryStore(stix_data=domain_data["objects"])
        return gitmem
    # if Url:
    #     url = Collection(TAXIIUrl)
    #     ts = TAXIICollectionSource(TAXIIUrl)
    #     src.add_data_source(ts)
    else:
        raise ValueError("DataSources not provided or not valid")
    


def get_groups(scheme: MemoryStore) -> list:
    return scheme.query([Filter("type", "=", "intrusion-set")])


def get_techniques_or_subtechniques(scheme: MemoryStore, include="both") -> list:
    """Filter Techniques or Sub-Techniques from ATT&CK Enterprise Domain.
    include argument has three options: "techniques", "subtechniques", or "both"
    depending on the intended behavior."""
    if include == "techniques":
        techs = scheme.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
    elif include == "subtechniques":
        techs = scheme.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True)
        ])
    elif include == "both":
        techs = scheme.query([
            Filter('type', '=', 'attack-pattern')
        ])
    else:
        raise RuntimeError("Unknown option %s!" % include)

    return techs


def get_software(scheme: MemoryStore) -> list:
    return list(chain.from_iterable(
        scheme.query(f) for f in [
            Filter("type", "=", "tool"), 
            Filter("type", "=", "malware")
        ]
    ))


def get_techniques_by_content(scheme: MemoryStore, content: str) -> list:
    techniques = scheme.query([ Filter('type', '=', 'attack-pattern') ])
    techniques_with_content = []
    i = 1
    for t in techniques:
        try:
            if content.lower() in t.description.lower():
                techniques_with_content.append(t)    
        except AttributeError:
            pass
    return techniques_with_content


def get_techniques_by_platform(scheme: MemoryStore, platform: str):
    return scheme.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('x_mitre_platforms', '=', platform)
    ])

def get_tactic_techniques(scheme: MemoryStore, tactic: str):
    # double checking the kill chain is MITRE ATT&CK
    # note: kill_chain_name is different for other domains:
    #    - enterprise: "mitre-attack"
    #    - mobile: "mitre-mobile-attack"
    #    - ics: "mitre-ics-attack"
    # supported type of tactics:
    #  - initial-access
    #  - persistence
    #  - collection
    #  - execution
    #  - privilege-escalation
    #  - defense-evasion
    #  - lateral-movement
    #  - execution
    #  - credential-access
    #  - impact
    #  - exfiltration
    #  - discovery
    #  - resource-development
    #  - reconnaissance
    #  - command-and-control

    return scheme.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', tactic),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
    ])

def get_related(thesrc, src_type, rel_type, target_type, reverse=False):
    """build relationship mappings
       params:
         thesrc: MemoryStore to build relationship lookups for
         src_type: source type for the relationships, e.g "attack-pattern"
         rel_type: relationship type for the relationships, e.g "uses"
         target_type: target type for the relationship, e.g "intrusion-set"
         reverse: build reverse mapping of target to source
    """

    relationships = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type)
    ])

    # stix_id => [ { relationship, related_object_id } for each related object ]
    id_to_related = {} 

    # build the dict
    for relationship in relationships:
        if (src_type in relationship.source_ref and target_type in relationship.target_ref):
            if (relationship.source_ref in id_to_related and not reverse) or (relationship.target_ref in id_to_related and reverse):
                # append to existing entry
                if not reverse: 
                    id_to_related[relationship.source_ref].append({
                        "relationship": relationship,
                        "id": relationship.target_ref
                    })
                else: 
                    id_to_related[relationship.target_ref].append({
                        "relationship": relationship, 
                        "id": relationship.source_ref
                    })
            else: 
                # create a new entry
                if not reverse: 
                    id_to_related[relationship.source_ref] = [{
                        "relationship": relationship, 
                        "id": relationship.target_ref
                    }]
                else:
                    id_to_related[relationship.target_ref] = [{
                        "relationship": relationship, 
                        "id": relationship.source_ref
                    }]
    # all objects of relevant type
    if not reverse:
        targets = thesrc.query([
            Filter('type', '=', target_type),
        ])
    else:
        targets = thesrc.query([
            Filter('type', '=', src_type),
        ])
    
    # remove revoked and deprecated objects from output
    targets = list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            targets
        )
    )

    # build lookup of stixID to stix object
    id_to_target = {}
    for target in targets:
        id_to_target[target.id] = target

    # build final output mappings
    output = {}
    for stix_id in id_to_related:
        value = []
        for related in id_to_related[stix_id]:
            if not related["id"] in id_to_target:
                continue # targeting a revoked object
            value.append({
                "object": id_to_target[related["id"]],
                "relationship": related["relationship"]
            })
        output[stix_id] = value
    return output


# software:group
def software_used_by_groups(thesrc):
    """returns group_id => {software, relationship} for each software used by the group."""
    x = get_related(thesrc, "intrusion-set", "uses", "malware")
    x_tool = get_related(thesrc, "intrusion-set", "uses", "tool")
    for key in x_tool:
      if key in x:
        x[key].extend(x_tool[key])
      else:
        x[key] = x_tool[key]
    return x

def groups_using_software(thesrc):
    """returns software_id => {group, relationship} for each group using the software."""
    x = get_related(thesrc, "intrusion-set", "uses", "tool", reverse=True)
    x.update(get_related(thesrc, "intrusion-set", "uses", "malware", reverse=True))
    return x

# technique:group
def techniques_used_by_groups(thesrc):
    """returns group_id => {technique, relationship} for each technique used by the group."""
    return get_related(thesrc, "intrusion-set", "uses", "attack-pattern")

def groups_using_technique(thesrc):
    """returns technique_id => {group, relationship} for each group using the technique."""
    return get_related(thesrc, "intrusion-set", "uses", "attack-pattern", reverse=True)

# technique:software
def techniques_used_by_software(thesrc):
    """return software_id => {technique, relationship} for each technique used by the software."""
    x = get_related(thesrc, "malware", "uses", "attack-pattern")
    x.update(get_related(thesrc, "tool", "uses", "attack-pattern"))
    return x

def software_using_technique(thesrc):
    """return technique_id  => {software, relationship} for each software using the technique."""
    x = get_related(thesrc, "malware", "uses", "attack-pattern", reverse=True)
    x_tool = get_related(thesrc, "tool", "uses", "attack-pattern", reverse=True)
    for key in x_tool:
      if key in x:
        x[key].extend(x_tool[key])
      else:
        x[key] = x_tool[key]
    return x

# technique:mitigation
def mitigation_mitigates_techniques(thesrc):
    """return mitigation_id => {technique, relationship} for each technique mitigated by the mitigation."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=False)

def technique_mitigated_by_mitigations(thesrc):
    """return technique_id => {mitigation, relationship} for each mitigation of the technique."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=True)

# technique:sub-technique
def subtechniques_of(thesrc):
    """return technique_id => {subtechnique, relationship} for each subtechnique of the technique."""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern", reverse=True)

def parent_technique_of(thesrc):
    """return subtechnique_id => {technique, relationship} describing the parent technique of the subtechnique"""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern")[0]

# technique:data-component
def datacomponent_detects_techniques(thesrc):
    """return datacomponent_id => {technique, relationship} describing the detections of each data component"""
    return get_related(thesrc, "x-mitre-data-component", "detects", "attack-pattern")

def technique_detected_by_datacomponents(thesrc):
    """return technique_id => {datacomponent, relationship} describing the data components that can detect the technique"""
    return get_related(thesrc, "x-mitre-data-component", "detects", "attack-pattern", reverse=True)


def get_techniques_by_group_software(thesrc, group_stix_id):
    # get the malware, tools that the group uses
    group_uses = [
        r for r in thesrc.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]

    # get the technique stix ids that the malware, tools use
    software_uses = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])

    #get the techniques themselves
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])

## techs_to_groups = groups_using_technique(src)

def related_threat_actors(attack_patterns: dict, techs_to_groups: dict):
    related_groups = dict()
    groups_techs = dict()
    for pid in attack_patterns.keys():
        if pid in techs_to_groups.keys():
            all_groups_by_pid_tech = techs_to_groups[pid]
            for group in all_groups_by_pid_tech:
                group_name = group['object']['name']
                if group_name not in related_groups.keys():
                    related_groups[group_name] = 1
                    groups_techs[group_name] = [attack_patterns[pid]]
                else:
                    related_groups[group_name] += 1
                    groups_techs[group_name].append(attack_patterns[pid])
    related_groups = {k: v for k, v in sorted(related_groups.items(), key=lambda item: item[1], reverse=True)}
    return list(related_groups.items())[0:10], groups_techs


def main_threat_actors(layer_path: str) -> list:
    ids = layer_convertion(layer_path, url=True)
    if isinstance(ids, str):
        return ids
    print("Wait For It...")
    src = InitializeDatasource()
    pattern_ids = convert_layer_data(ids, src)
    techs = groups_using_technique(src) # get all techniques from matrix
    if isinstance(pattern_ids, str):
        return pattern_ids
    related_groups, groups_techs = related_threat_actors(pattern_ids, techs)
    return related_groups


# print(main_threat_actors('http://localhost/NewIncident.json'))



