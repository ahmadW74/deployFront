
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os
import dns.resolver
import dns.name
import dns.rdatatype
import dns.dnssec
import dns.message
import dns.query
import socket
import sys
import argparse
import json
import datetime
from typing import List, Dict, Any, Optional, Tuple
import binascii
import hashlib
import base64
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
app = FastAPI()
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
data=[]
with open("C:\\Users\\ahmad\\Desktop\\lockedin\\src\\data.txt", "r") as file:
    data =[line.strip().split(":") for line in file.readlines()]
    print(data)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
app.mount("/assets", StaticFiles(directory="dist/assets"), name="assets")
class DNSSECAnalyzer:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.use_edns(0, dns.flags.DO, 4096)
        
    def get_algorithm_name(self, alg_num: int) -> str:
        """Convert algorithm number to human-readable name"""
        algorithms = {
            1: "RSAMD5",
            3: "DSA",
            5: "RSASHA1",
            6: "DSA-NSEC3-SHA1",
            7: "RSASHA1-NSEC3-SHA1",
            8: "RSASHA256",
            10: "RSASHA512",
            12: "ECC-GOST",
            13: "ECDSAP256SHA256",
            14: "ECDSAP384SHA384",
            15: "ED25519",
            16: "ED448"
        }
        return algorithms.get(alg_num, f"Unknown({alg_num})")
    
    def get_digest_type_name(self, digest_type: int) -> str:
        """Convert digest type number to human-readable name"""
        digest_types = {
            1: "SHA-1",
            2: "SHA-256",
            3: "GOST R 34.11-94",
            4: "SHA-384"
        }
        return digest_types.get(digest_type, f"Unknown({digest_type})")
    
    def format_key_data(self, key_data: bytes) -> str:
        """Format key data for display"""
        b64_data = base64.b64encode(key_data).decode()
        # Split into 64-character lines
        lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
        return '\n                '.join(lines)
    
    def get_key_size(self, key_data: bytes, algorithm: int) -> int:
        """Estimate key size based on key data and algorithm"""
        if algorithm in [5, 7, 8, 10]:  # RSA algorithms
            # For RSA, key size is roughly the bit length of the modulus
            # This is a rough estimation
            return len(key_data) * 8 // 10  # Approximate
        elif algorithm in [13, 14]:  # ECDSA
            if algorithm == 13:  # P-256
                return 256
            elif algorithm == 14:  # P-384
                return 384
        elif algorithm == 15:  # Ed25519
            return 255
        elif algorithm == 16:  # Ed448
            return 448
        return len(key_data) * 8
    
    def query_with_dnssec(self, domain: str, record_type: str) -> Optional[dns.message.Message]:
        """Query DNS with DNSSEC validation"""
        try:
            query = dns.message.make_query(domain, record_type, want_dnssec=True)
            query.flags |= dns.flags.AD
            
            # Try multiple nameservers
            nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            
            for ns in nameservers:
                try:
                    response = dns.query.udp(query, ns, timeout=10)
                    if response:
                        return response
                except Exception:
                    continue
                    
            return None
        except Exception as e:
            print(f"Error querying {domain} {record_type}: {e}")
            return None
    
    def get_nsec_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get NSEC records for a domain"""
        nsec_records = []
        try:
            # Try both NSEC and NSEC3
            for record_type in ['NSEC', 'NSEC3']:
                response = self.query_with_dnssec(domain, record_type)
                if not response:
                    continue
                    
                for rrset in response.answer:
                    if rrset.rdtype == getattr(dns.rdatatype, record_type):
                        for rdata in rrset:
                            if record_type == 'NSEC':
                                nsec_records.append({
                                    'type': 'NSEC',
                                    'next_domain': str(rdata.next),
                                    'types': [dns.rdatatype.to_text(t) for t in rdata.windows],
                                    'ttl': rrset.ttl,
                                    'owner': str(rrset.name)
                                })
                            elif record_type == 'NSEC3':
                                nsec_records.append({
                                    'type': 'NSEC3',
                                    'hash_algorithm': rdata.algorithm,
                                    'flags': rdata.flags,
                                    'iterations': rdata.iterations,
                                    'salt': binascii.hexlify(rdata.salt).decode().upper() if rdata.salt else '',
                                    'next_hashed_owner': binascii.hexlify(rdata.next).decode().upper(),
                                    'types': [dns.rdatatype.to_text(t) for t in rdata.windows],
                                    'ttl': rrset.ttl,
                                    'owner': str(rrset.name)
                                })
                                
            # Also check authority section for NSEC records (common in NXDOMAIN responses)
            for record_type in ['NSEC', 'NSEC3']:
                response = self.query_with_dnssec(f"nonexistent.{domain}", 'A')
                if response and response.authority:
                    for rrset in response.authority:
                        if rrset.rdtype == getattr(dns.rdatatype, record_type):
                            for rdata in rrset:
                                record_data = {
                                    'type': record_type,
                                    'ttl': rrset.ttl,
                                    'owner': str(rrset.name),
                                    'source': 'authority_section'
                                }
                                
                                if record_type == 'NSEC':
                                    record_data.update({
                                        'next_domain': str(rdata.next),
                                        'types': [dns.rdatatype.to_text(t) for t in rdata.windows]
                                    })
                                elif record_type == 'NSEC3':
                                    record_data.update({
                                        'hash_algorithm': rdata.algorithm,
                                        'flags': rdata.flags,
                                        'iterations': rdata.iterations,
                                        'salt': binascii.hexlify(rdata.salt).decode().upper() if rdata.salt else '',
                                        'next_hashed_owner': binascii.hexlify(rdata.next).decode().upper(),
                                        'types': [dns.rdatatype.to_text(t) for t in rdata.windows]
                                    })
                                
                                # Avoid duplicates
                                if record_data not in nsec_records:
                                    nsec_records.append(record_data)
                                    
        except Exception as e:
            print(f"Error getting NSEC records for {domain}: {e}")
        
        return nsec_records
    
    def get_ds_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get DS records for a domain"""
        ds_records = []
        try:
            response = self.query_with_dnssec(domain, 'DS')
            if not response:
                return ds_records
                
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DS:
                    for rdata in rrset:
                        ds_records.append({
                            'key_tag': rdata.key_tag,
                            'algorithm': rdata.algorithm,
                            'algorithm_name': self.get_algorithm_name(rdata.algorithm),
                            'digest_type': rdata.digest_type,
                            'digest_type_name': self.get_digest_type_name(rdata.digest_type),
                            'digest': binascii.hexlify(rdata.digest).decode().upper(),
                            'ttl': rrset.ttl
                        })
        except Exception as e:
            print(f"Error getting DS records for {domain}: {e}")
        
        return ds_records
    
    def determine_key_role(self, dnskey, all_dnskeys: List) -> Dict[str, Any]:
        """Determine the role of a DNSKEY (ZSK, KSK, or both)"""
        is_sep = bool(dnskey['flags'] & 1)  # Secure Entry Point flag
        key_tag = dnskey['key_tag']
        
        # Default role assignment
        if is_sep:
            primary_role = "KSK"
            secondary_role = None
        else:
            primary_role = "ZSK"
            secondary_role = None
        
        # Check if this key is referenced by DS records
        # This would be done by comparing key tags, but we need DS records from parent
        # For now, we use the SEP flag as primary indicator
        
        # Additional heuristics
        roles = []
        if is_sep:
            roles.append("KSK")
        
        # Keys without SEP flag are typically ZSKs
        if not is_sep:
            roles.append("ZSK")
        
        # Some keys can serve dual roles
        if len(all_dnskeys) == 1:
            # Single key setup - likely serves both roles
            roles = ["ZSK", "KSK"] if is_sep else ["ZSK"]
            primary_role = "ZSK/KSK" if is_sep else "ZSK"
        
        return {
            'primary_role': primary_role,
            'all_roles': roles,
            'is_sep': is_sep,
            'is_ksk': 'KSK' in roles,
            'is_zsk': 'ZSK' in roles,
            'role_confidence': 'high' if is_sep or not is_sep else 'medium'
        }
    
    def get_dnskey_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get DNSKEY records for a domain"""
        dnskey_records = []
        try:
            response = self.query_with_dnssec(domain, 'DNSKEY')
            if not response:
                return dnskey_records
                
            # First pass: collect all DNSKEY data
            raw_keys = []
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    for rdata in rrset:
                        key_size = self.get_key_size(rdata.key, rdata.algorithm)
                        key_tag = dns.dnssec.key_id(rdata)
                        
                        raw_keys.append({
                            'flags': rdata.flags,
                            'protocol': rdata.protocol,
                            'algorithm': rdata.algorithm,
                            'algorithm_name': self.get_algorithm_name(rdata.algorithm),
                            'key_tag': key_tag,
                            'key_size': key_size,
                            'key_data': rdata.key,
                            'key_data_b64': self.format_key_data(rdata.key),
                            'key_data_hex': binascii.hexlify(rdata.key).decode().upper(),
                            'is_sep': bool(rdata.flags & 1),  # Secure Entry Point
                            'ttl': rrset.ttl
                        })
            
            # Second pass: determine roles for each key
            for i, key in enumerate(raw_keys):
                role_info = self.determine_key_role(key, raw_keys)
                
                dnskey_records.append({
                    'flags': key['flags'],
                    'protocol': key['protocol'],
                    'algorithm': key['algorithm'],
                    'algorithm_name': key['algorithm_name'],
                    'key_tag': key['key_tag'],
                    'key_size': key['key_size'],
                    'key_data_b64': key['key_data_b64'],
                    'key_data_hex': key['key_data_hex'],
                    'is_sep': key['is_sep'],
                    'ttl': key['ttl'],
                    'role': role_info['primary_role'],
                    'all_roles': role_info['all_roles'],
                    'is_ksk': role_info['is_ksk'],
                    'is_zsk': role_info['is_zsk'],
                    'role_confidence': role_info['role_confidence'],
                    'key_order': i + 1,  # Order in the response
                    'key_hierarchy_level': 'primary' if role_info['is_ksk'] else 'signing'
                })
                
        except Exception as e:
            print(f"Error getting DNSKEY records for {domain}: {e}")
        
        return dnskey_records
    
    def get_ns_records(self, domain: str) -> List[str]:
        """Get NS records for a domain"""
        ns_records = []
        try:
            response = self.query_with_dnssec(domain, 'NS')
            if not response:
                return ns_records
                
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.NS:
                    for rdata in rrset:
                        ns_records.append(str(rdata.target))
        except Exception as e:
            print(f"Error getting NS records for {domain}: {e}")
        
        return ns_records
    
    def get_soa_records(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get SOA record for a domain"""
        try:
            response = self.query_with_dnssec(domain, 'SOA')
            if not response:
                return None
                
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    rdata = rrset[0]
                    return {
                        'mname': str(rdata.mname),
                        'rname': str(rdata.rname),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum,
                        'ttl': rrset.ttl
                    }
        except Exception as e:
            print(f"Error getting SOA record for {domain}: {e}")
        
        return None
    
    def build_chain_of_trust(self, domain: str) -> List[Dict[str, Any]]:
        """Build the complete DNSSEC chain of trust from root to domain"""
        # First, build the hierarchy from domain to root
        hierarchy = []
        current_domain = dns.name.from_text(domain)
        
        # Build the full hierarchy including the target domain
        while len(current_domain) >= 0:
            domain_str = str(current_domain).rstrip('.')
            
            # Add root domain
            if not domain_str:
                hierarchy.append('.')
                break
            else:
                hierarchy.append(domain_str)
            
            # Move to parent domain
            if len(current_domain) == 0:
                break
            current_domain = current_domain.parent()
        
        # Reverse to get root -> TLD -> domain order
        hierarchy.reverse()
        
        chain = []
        for domain_str in hierarchy:
            print(f"Analyzing: {domain_str if domain_str != '.' else 'ROOT'}")
            
            # Get all relevant records
            ds_records = self.get_ds_records(domain_str)
            dnskey_records = self.get_dnskey_records(domain_str)
            ns_records = self.get_ns_records(domain_str)
            soa_record = self.get_soa_records(domain_str)
            nsec_records = self.get_nsec_records(domain_str)
            
            chain.append({
                'domain': domain_str,
                'display_name': 'ROOT' if domain_str == '.' else domain_str,
                'ds_records': ds_records,
                'dnskey_records': dnskey_records,
                'ns_records': ns_records,
                'soa_record': soa_record,
                'nsec_records': nsec_records
            })
        
        return chain
    
    def create_json_output(self, chain: List[Dict[str, Any]], target_domain: str) -> Dict[str, Any]:
        """Create a comprehensive JSON structure for frontend consumption"""
        
        # Process each level in the chain
        levels = []
        for i, level in enumerate(chain):
            domain = level['domain']
            display_name = level['display_name']
            
            # Determine domain type
            domain_type = "root"
            if domain == '.':
                domain_type = "root"
            elif i == 1 and len(chain) > 2:
                domain_type = "tld"
            elif i == len(chain) - 1 and i > 0:
                domain_type = "target"
            else:
                domain_type = "subdomain"
            
            # Calculate DNSSEC status
            has_ds = bool(level['ds_records'])
            has_dnskey = bool(level['dnskey_records'])
            has_nsec = bool(level['nsec_records'])
            
            if domain == '.':  # Root zone special case
                status = "signed" if has_dnskey else "unsigned"
                status_message = "Root zone is signed (trust anchor)" if has_dnskey else "Root zone DNSKEY not found"
                status_type = "success" if has_dnskey else "error"
            elif has_ds and has_dnskey:
                status = "signed"
                status_message = "Fully signed with DNSSEC"
                status_type = "success"
            elif has_dnskey:
                status = "partial"
                status_message = "Has DNSKEY but no DS record (unsigned delegation)"
                status_type = "warning"
            elif has_ds:
                status = "partial"
                status_message = "Has DS record but no DNSKEY found"
                status_type = "warning"
            else:
                status = "unsigned"
                status_message = "No DNSSEC records found"
                status_type = "error"
            
            # Add NSEC information to status
            if has_nsec:
                status_message += f" (NSEC records present)"
            
            # Process DNSKEY records for hierarchy info
            ksk_keys = [k for k in level['dnskey_records'] if k['is_ksk']]
            zsk_keys = [k for k in level['dnskey_records'] if k['is_zsk']]
            
            # Create level object
            level_obj = {
                "id": f"level_{i}",
                "index": i,
                "domain": domain,
                "display_name": display_name,
                "domain_type": domain_type,
                "dnssec_status": {
                    "status": status,
                    "message": status_message,
                    "type": status_type,
                    "has_ds": has_ds,
                    "has_dnskey": has_dnskey,
                    "has_nsec": has_nsec
                },
                "key_hierarchy": {
                    "ksk_count": len(ksk_keys),
                    "zsk_count": len(zsk_keys),
                    "total_keys": len(level['dnskey_records']),
                    "ksk_keys": ksk_keys,
                    "zsk_keys": zsk_keys
                },
                "records": {
                    "ds_records": level['ds_records'],
                    "dnskey_records": level['dnskey_records'],
                    "ns_records": level['ns_records'],
                    "soa_record": level['soa_record'],
                    "nsec_records": level['nsec_records']
                },
                "delegation": {
                    "delegates_to": chain[i + 1]['display_name'] if i < len(chain) - 1 else None,
                    "delegated_from": chain[i - 1]['display_name'] if i > 0 else None
                },
                "chain_break_info": {
                    "has_chain_break": False,
                    "break_reason": None,
                    "nsec_evidence": level['nsec_records'] if level['nsec_records'] else None
                }
            }
            
            # Check for chain breaks
            if i > 0:  # Not root
                parent_level = chain[i - 1]
                parent_has_ds = bool(parent_level['ds_records'])
                
                if not parent_has_ds and domain != '.':
                    level_obj["chain_break_info"]["has_chain_break"] = True
                    level_obj["chain_break_info"]["break_reason"] = "Missing DS record in parent zone"
                elif not has_dnskey and parent_has_ds:
                    level_obj["chain_break_info"]["has_chain_break"] = True
                    level_obj["chain_break_info"]["break_reason"] = "DS record exists but DNSKEY not found"
            
            levels.append(level_obj)
        
        # Calculate summary statistics
        signed_levels = sum(1 for level in chain if level['dnskey_records'])
        total_levels = len(chain)
        
        # Check for broken chain
        chain_status = "complete"
        chain_message = "Full DNSSEC validation possible"
        
        broken_chain = False
        chain_breaks = []
        
        for i, level_obj in enumerate(levels[1:], 1):  # Skip root
            if level_obj["chain_break_info"]["has_chain_break"]:
                broken_chain = True
                chain_breaks.append({
                    "level": i,
                    "domain": level_obj["domain"],
                    "reason": level_obj["chain_break_info"]["break_reason"]
                })
        
        if broken_chain:
            chain_status = "broken"
            chain_message = f"Chain break detected at {len(chain_breaks)} level(s)"
        elif signed_levels < total_levels:
            chain_status = "incomplete"
            chain_message = "Some levels unsigned"
        
        # Create relationships for graph visualization
        relationships = []
        for i in range(len(levels) - 1):
            current_level = levels[i]
            next_level = levels[i + 1]
            
            # Determine relationship type based on DS records
            relationship_type = "delegation"
            relationship_status = "valid"
            
            if current_level['dnssec_status']['has_ds'] or current_level['domain_type'] == 'root':
                if next_level['dnssec_status']['has_dnskey']:
                    relationship_status = "valid"
                else:
                    relationship_status = "broken"
            else:
                relationship_status = "unsigned"
            
            relationships.append({
                "id": f"rel_{i}",
                "from": current_level['id'],
                "to": next_level['id'],
                "from_domain": current_level['display_name'],
                "to_domain": next_level['display_name'],
                "type": relationship_type,
                "status": relationship_status
            })
        
        # Create comprehensive JSON structure
        result = {
            "metadata": {
                "target_domain": target_domain,
                "analysis_timestamp": datetime.datetime.now().isoformat(),
                "chain_length": total_levels,
                "signed_levels": signed_levels,
                "chain_status": chain_status,
                "chain_message": chain_message
            },
            "chain_summary": {
                "total_levels": total_levels,
                "signed_levels": signed_levels,
                "unsigned_levels": total_levels - signed_levels,
                "chain_complete": chain_status == "complete",
                "chain_breaks": chain_breaks,
                "security_status": {
                    "overall_status": chain_status,
                    "message": chain_message,
                    "type": "success" if chain_status == "complete" else "warning" if chain_status == "incomplete" else "error"
                }
            },
            "levels": levels,
            "relationships": relationships,
            "graph_data": {
                "nodes": [
                    {
                        "id": level['id'],
                        "label": level['display_name'],
                        "domain": level['domain'],
                        "type": level['domain_type'],
                        "status": level['dnssec_status']['status'],
                        "status_type": level['dnssec_status']['type'],
                        "has_ds": level['dnssec_status']['has_ds'],
                        "has_dnskey": level['dnssec_status']['has_dnskey'],
                        "has_nsec": level['dnssec_status']['has_nsec'],
                        "ds_count": len(level['records']['ds_records']),
                        "dnskey_count": len(level['records']['dnskey_records']),
                        "ns_count": len(level['records']['ns_records']),
                        "nsec_count": len(level['records']['nsec_records']),
                        "ksk_count": level['key_hierarchy']['ksk_count'],
                        "zsk_count": level['key_hierarchy']['zsk_count'],
                        "has_chain_break": level['chain_break_info']['has_chain_break']
                    }
                    for level in levels
                ],
                "edges": [
                    {
                        "id": rel['id'],
                        "source": rel['from'],
                        "target": rel['to'],
                        "label": f"{rel['from_domain']} → {rel['to_domain']}",
                        "type": rel['type'],
                        "status": rel['status'],
                        "animated": rel['status'] == "valid"
                    }
                    for rel in relationships
                ]
            }
        }
        
        return result

def analyze_dnssec_chain(domain: str) -> Dict[str, Any]:
    """
    Main function to analyze DNSSEC chain for a domain.
    Returns a dictionary with complete analysis data suitable for frontend consumption.
    
    Args:
        domain (str): Domain name to analyze
        
    Returns:
        Dict[str, Any]: Complete analysis data including success status
    """
    try:
        # Normalize domain name
        domain = domain.lower().rstrip('.')
        
        analyzer = DNSSECAnalyzer()
        chain = analyzer.build_chain_of_trust(domain)
        
        if not chain:
            return {
                "success": False,
                "error": "Could not build chain of trust",
                "domain": domain
            }
        
        # Create JSON output for frontend
        json_data = analyzer.create_json_output(chain, domain)
        json_data["success"] = True
        
        return json_data
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "domain": domain
        }
@app.get("/chain/{domain}")
def get_item(domain:str):
    return analyze_dnssec_chain(domain)
@app.get("/")
async def serve_index():
    return FileResponse("dist/index.html")
@app.get("/login/{user}/{passw}")
def login(user:str,passw:str):
    entry=f"{user}:{passw}"
    print(entry)
    print(data)
    correct=False
    for i in data:
        if user in i and passw in i:
            print("ok")
            return {"success":i[0]}
    print("no")
    return {"success":"no"}
@app.get("/signup/{user}/{passw}/{name}")
def signup(user:str,passw:str,name:str):
    file_entry=f"{name}:{user}:{passw}"
    array_entry=[name,user,passw]
    data.append(array_entry)
    with open("C:\\Users\\ahmad\\Desktop\\lockedin\\src\\data.txt", "a") as file:
        file.write(f"\n{file_entry}")

class TokenPayload(BaseModel):
    token: str

@app.post("/google-auth")
def google_auth(payload: TokenPayload):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google client ID not configured")
    try:
        idinfo = id_token.verify_oauth2_token(
            payload.token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )
        email = idinfo.get("email")
        name = idinfo.get("name", email)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token")

    for entry in data:
        if len(entry) > 1 and entry[1] == email:
            return {"success": entry[0], "email": email}

    file_entry = f"{name}:{email}:"
    array_entry = [name, email, ""]
    data.append(array_entry)
    with open("C:\\Users\\ahmad\\Desktop\\lockedin\\src\\data.txt", "a") as file:
        file.write(f"\n{file_entry}")

    return {"success": name, "email": email}
    
#uvicorn main:app --reload