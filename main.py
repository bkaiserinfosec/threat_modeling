import csv
import json


class ThreatModeler(object):
    def __init__(self):
        self.elements = {}

    def run(self):
        self.get_input()
        self.process_input()
        self.find_threats()

    def get_input(self):
        # Sample Application
        self.elements['Sample App'] = {'conditions': [], 'threats': [], 'data': {'formats': [], 'categories': [], 'classification': ''}}
        # The type of review: Application, System, Network, Other
        self.elements['Sample App']['Type'] = 'Application'
        # Dynamic - The type of Application: Web, API, Mobile, Other
        self.elements['Sample App']['Implements API'] = 'Yes'
        # Dynamic - Uses Session Tokens: Yes, No, Not Sure
        self.elements['Sample App']['Uses Session Tokens'] = 'Yes'
        # Processed Data Formats
        self.elements['Sample App']['Processed Data Formats'] = [
            'JSON'
        ]
        # Environment
        self.elements['Sample App']['Environment'] = 'Production'

        # Sample Database
        self.elements['Sample Database'] = {'conditions': [], 'threats': [], 'data': {'formats': [], 'categories': [], 'classification': ''}}
        # The type of review: Application, System, Network, Other
        self.elements['Sample Database']['Type'] = 'Database'
        # Dynamic - The type of Application: Web, API, Mobile, Other
        self.elements['Sample Database']['Uses SQL'] = 'Yes'

        # Sample Dataflow





    def process_input(self):
        with open('input_to_conditions_mapping.json') as f_in:
            input = json.load(f_in)
        for e in self.elements:
            for i in self.elements[e]:
                for j in input:
                    if i == j['input']:
                        if self.elements[e][i] == 'Yes':
                            self.elements[e]['conditions'].append(f'target.{j["condition"]} is True')
                        elif self.elements[e][i] == 'No':
                            self.elements[e]['conditions'].append(f'target.{j["condition"]} is False')
                        else:
                            self.elements[e]['conditions'].append(f'target.{j["condition"]} == \'{self.elements[e][i]}\'')
            self.map_dfd_type()
            self.elements[e] = self.apply_default_controls(self.elements[e])
            self.elements[e] = self.apply_data(self.elements[e])

    def apply_data(self, element):
        if 'Processed Data Formats' in element:
            for format in element['Processed Data Formats']:
                element['data']['formats'].append(format)
        return element


    def apply_default_controls(self, element):
        lambda_controls, process_controls, server_controls, dataflow_controls, datastore_controls = self.read_controls_csv()
        if element['DFDType'] == 'Lambda':
            element = self.apply_control_handler(element, lambda_controls)
        elif element['DFDType'] == 'Process':
            element = self.apply_control_handler(element, process_controls)
        elif element['DFDType'] == 'Server':
            element = self.apply_control_handler(element, server_controls)
        elif element['DFDType'] == 'Dataflow':
            element = self.apply_control_handler(element, dataflow_controls)
        elif element['DFDType'] == 'Datastore':
            element = self.apply_control_handler(element, datastore_controls)
        return element

    def apply_control_handler(self, element, controlset):
        for control in controlset:
            control_dict = controlset[control]
            if control_dict['type'] == 'bool':
                element['conditions'].append(
                    f'target.controls.{control} is False'
                )
            elif control_dict['type'] == 'text':
                element['conditions'].append(
                    f'target.controls.{control} == ""'
                )
        return element

    def map_dfd_type(self):
        for e in self.elements:
            elem_type = self.elements[e]['Type']
            if elem_type == 'Application':
                self.elements[e]['DFDType'] = 'Process'
            elif elem_type == 'Database':
                self.elements[e]['DFDType'] = 'Datastore'
            else:
                print('placeholder for more element types')

    def find_threats(self):

        threats = self.read_threats_csv()
        for e in self.elements:
            elem_type = self.elements[e]['DFDType']
            for threat in threats:
                if elem_type in threat['target']:
                    match = self.condition_check(self.elements[e], self.elements[e]['conditions'], threat['condition'])
                    if match:
                        self.elements[e]['threats'].append(threat)
            print('THREATS FOR ' + e)
            for threat in self.elements[e]['threats']:
                print(threat['description'])
            controls, applied_solutions, threats_mitigated = self.generate_threat_control_options(self.elements[e]['threats'], self.elements[e])

    def condition_check(self, element, elem_conditions, threat_conditions):
        match = True
        all_must_match, any_can_match, all_must_not_match, any_can_not_match = self.parse_json_conditions(threat_conditions)

        string_match = False
        if '!=' in threat_conditions or '==' in threat_conditions:
            string_match = True


        if all_must_match:
            if any_can_match:
                for req in all_must_match:
                    if req not in elem_conditions:
                        match = False
                if match:
                    any_matches = False
                    for req in any_can_match:
                        if req in elem_conditions:
                            any_matches = True
                    if not any_matches:
                        match = False
                if all_must_not_match:
                    print()
                elif any_can_not_match:
                    print()
            elif all_must_not_match:
                print()
            elif any_can_not_match:
                print()
            else:
                for req in all_must_match:
                    if '=' in req:
                        if ' for d in target.data)' in req: # means it is a data requirement
                            if 'd.format ==' in req:
                                elem = req.split("d.format == '")[1].split("'")[0]
                                if elem not in element['data']['formats']:
                                    match = False
                            else:
                                print()
                        else:
                            if req.endswith("'"):  # Example: target.environment == "Production"
                                if ' == ' in req:
                                    if req not in element['conditions']:
                                        match = False
                                else:
                                    if req.replace('!=', '==') in element['conditions']:
                                        match = False
                            else:
                                print()
                    else:
                        if req not in elem_conditions:
                            match = False
        elif any_can_match:
            if all_must_not_match:
                print()
            elif any_can_not_match:
                print()
            else:
                any_matches = False
                for req in any_can_match:
                    if req in elem_conditions:
                        any_matches = True
                if not any_matches:
                    match = False
        elif all_must_not_match:
            if any_can_not_match:
                print()
        elif any_can_not_match:
            print()

        return match

    def parse_json_conditions(self, raw_conditions):
        all_must_match = []
        any_can_match = []
        all_must_not_match = []
        any_can_not_match = []
        if raw_conditions.startswith('('):
            if ') and ' in raw_conditions:
                placeholder = raw_conditions.split(') and ')[1]
                parenth = raw_conditions.split(') and ')[0]
                raw_conditions = placeholder + ' and ' + parenth + ')'
            elif ') or ' in raw_conditions:
                print()
        if ' (' in raw_conditions:
            parenthesis_cnt = raw_conditions.count('(')
            if parenthesis_cnt == 1:
                parenthesis_modifier = raw_conditions.split(' (')[0]
                all_words = parenthesis_modifier.split()
                parenthesis_modifier = all_words[len(all_words)-1]
                if parenthesis_modifier != 'and' and parenthesis_modifier != 'or':
                    print()
                parenthesis_portion = raw_conditions.split(' (')[1].replace('(', '').replace(')', '')
                if parenthesis_modifier == 'and':
                    prefix = raw_conditions.split(' and (')[0]
                    all_must_match.append(prefix)
                    if ' and ' in parenthesis_portion:
                        if ' or ' in parenthesis_portion:
                            print()
                        else:
                            print()
                    elif ' or ' in parenthesis_portion:
                        if ' and ' in parenthesis_portion:
                            print()
                        else:
                            parts = parenthesis_portion.split(' or ')
                            for i in parts:
                                any_can_match.append(i)
                    else:
                        print()
                else:
                    print()
            else:
                print()
        else:
            if ' and ' in raw_conditions:
                if ' or ' in raw_conditions:
                    print()
                else:
                    all = raw_conditions.split(' and ')
                    for i in all:
                        all_must_match.append(i)
            elif ' or ' in raw_conditions:
                if ' and ' in raw_conditions:
                    print()
                else:
                    parts = raw_conditions.split(' or ')
                    for i in parts:
                        any_can_match.append(i)
            else:
                all_must_match.append(raw_conditions)
        return all_must_match, any_can_match, all_must_not_match, any_can_not_match

    def generate_threat_control_options(self, threats, element):
        controls = []
        applied_solutions = []
        threats_mitigated = []
        solutions = self.read_solutions_csv(element)
        for threat in threats:
            threat_id = threat['SID']
            for solution in solutions:
                solution_id = list(solution.keys())[0]
                if (solution_id == threat_id):
                    threat_target_str = ','.join(threat['target'])
                    if (solution[solution_id]['solution_target'] in threat_target_str):
                        applied_solutions.append(solution)
                        threats_mitigated.append(threat_id)
        for solution in applied_solutions:
            control = solution[list(solution.keys())[0]]['solution']
            if control not in controls:
                controls.append(control)
        return controls, applied_solutions, threats_mitigated

    def generate_threats_csv(self):
        with open('threats.json', errors='ignore') as f_in:
            threats = json.load(f_in)
        with open('threat_report.csv', 'w', newline='') as f_out:
            csv_writer = csv.writer(f_out)
            for t in threats:
                row = [
                    t['SID'], ", ".join(t['target']), t['description'], t['details'],
                    t['Likelihood of Attack'] if 'Likelihood of Attack' in t else '',
                    t['severity'], t['condition'], t['prerequisites'], t['mitigations'], t['example'], t['references']
                ]
                csv_writer.writerow(row)

    def read_threats_csv(self):
        json_threats = []
        with open('threats.csv', 'r', errors='ignore') as f_in:
            csv_lines = csv.reader(f_in)
            line_count = 0
            for l in csv_lines:
                if line_count != 0:
                    targets = l[1].split(', ')
                    new = {
                        "SID": l[0],
                        "target": targets,
                        "description": l[2],
                        "details": l[3],
                        "Likelihood Of Attack": l[4],
                        "severity": l[5],
                        "condition": l[6],
                        "prerequisites": l[7],
                        "mitigations": l[8],
                        "example": l[9],
                        "references": l[10]
                    }
                    json_threats.append(new)
                line_count +=1
        return json_threats

    def read_controls_csv(self):
        lambda_controls = {}
        process_controls = {}
        server_controls = {}
        dataflow_controls = {}
        datastore_controls = {}
        with open('controls.csv', 'r', errors='ignore') as f_in:
            csv_lines = csv.reader(f_in)
            line_count = 0
            for l in csv_lines:
                if line_count != 0:
                    new = {
                        l[0]: {
                            'type': l[1],
                            'description': l[2]
                        }
                    }
                    if l[3]:
                        lambda_controls[l[0]] = {
                            'type': l[1],
                            'description': l[2]
                        }
                    if l[4]:
                        process_controls[l[0]] = {
                            'type': l[1],
                            'description': l[2]
                        }
                    if l[5]:
                        server_controls[l[0]] = {
                            'type': l[1],
                            'description': l[2]
                        }
                    if l[6]:
                        dataflow_controls[l[0]] = {
                            'type': l[1],
                            'description': l[2]
                        }
                    if l[7]:
                        datastore_controls[l[0]] = {
                            'type': l[1],
                            'description': l[2]
                        }

                line_count += 1
        return lambda_controls, process_controls, server_controls, dataflow_controls, datastore_controls

    def read_solutions_csv(self, element):
        solutions = []
        with open('solutions.csv', 'r', errors='ignore') as f_in:
            csv_lines = csv.reader(f_in)
            line_count = 0
            for l in csv_lines:
                if line_count != 0:
                    if l[6]:
                        if l[1] == element['DFDType']:
                            new = {
                                l[0]: {
                                    'solution_target': l[1],
                                    'attribute': ", ".join(l[2]) if ',' in l[2] else l[2],
                                    'threat_description': l[3],
                                    'solution_type': l[4],
                                    'fix': l[5],
                                    'solution': l[6],
                                    'validation': l[7]


                                }
                            }
                            solutions.append(new)
                line_count += 1
        return solutions

ThreatModeler().run()
