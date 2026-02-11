import dns.resolver

def get_advanced_dns(domain: str):
    results = {}
    record_types = ['MX', 'TXT', 'NS']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results[rtype] = [str(rdata) for rdata in answers]
        except Exception:
            results[rtype] = []
            
    return results