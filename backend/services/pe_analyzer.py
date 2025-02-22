# services/pe_analyzer.py
def analyze_pe_sections(pe):
    suspicious = []
    for section in pe.sections:
        if section.get_entropy() > 7.0:
            suspicious.append({
                'name': section.Name.decode().strip('\x00'),
                'entropy': section.get_entropy(),
                'characteristics': hex(section.Characteristics)
            })
    return suspicious

def calculate_entropy(data):
    entropy = 0
    if not data:
        return 0
    for x in range(256):
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy