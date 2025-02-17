#!/usr/bin/env python3
import argparse
import requests
import json
import csv
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from tqdm import tqdm
from termcolor import colored
import hashlib
import piexif
from urllib.parse import urlparse
import time
import sys
from concurrent.futures import ThreadPoolExecutor
import warnings
import urllib3
import asyncio
import aiohttp

@dataclass
class HashResult:
    original_hash: str
    plaintext: Optional[str]
    algorithm: str
    salt: Optional[str] = None

class WordPressAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        self.session = requests.Session()
        self.base_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.api_key = api_key
        self._hash_cache = {}  # Cache pour les résultats de déchiffrement
        # Désactiver les avertissements SSL
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _get_bypass_headers(self) -> Dict[str, str]:
        """Return headers for rate limit bypass"""
        return {
            'X-Originating-IP': '127.0.0.1',
            'X-Forwarded-For': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Host': '127.0.0.1',
            'X-Forwarded-Host': '127.0.0.1'
        }

    def clean_domain(self, domain: str) -> str:
        """Clean domain URL by removing protocol and trailing slashes"""
        domain = domain.lower()
        domain = domain.replace('https://', '').replace('http://', '')
        domain = domain.rstrip('/')
        return domain

    def get_wordpress_users(self, domain: str, use_bypass: bool = False, verbose: bool = True) -> List[Dict]:
        """Fetch WordPress users from the given domain"""
        clean_domain = self.clean_domain(domain)
        url = f"https://{clean_domain}/wp-json/wp/v2/users"
        headers = self.base_headers.copy()
        
        if use_bypass:
            headers.update(self._get_bypass_headers())

        try:
            response = self.session.get(url, headers=headers, verify=False)  # Désactiver la vérification SSL
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            if verbose:
                print(colored(f"Erreur lors de la récupération des utilisateurs de {domain}: {str(e)}", 'red'))
            return []

    async def get_wordpress_users_async(self, domain: str, session: aiohttp.ClientSession, use_bypass: bool = False) -> List[Dict]:
        """Fetch WordPress users from the given domain asynchronously"""
        clean_domain = self.clean_domain(domain)
        url = f"https://{clean_domain}/wp-json/wp/v2/users"
        headers = self.base_headers.copy()
        
        if use_bypass:
            headers.update(self._get_bypass_headers())

        try:
            async with session.get(url, headers=headers, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    return await response.json()
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        return []

    def decrypt_hash(self, hash_value: str) -> Optional[HashResult]:
        """Decrypt a hash using hashes.com API with caching"""
        # Vérifier si le hash est déjà dans le cache
        if hash_value in self._hash_cache:
            return self._hash_cache[hash_value]

        if not self.api_key:
            result = HashResult(
                original_hash=hash_value,
                plaintext=None,
                algorithm='unknown'
            )
            self._hash_cache[hash_value] = result
            return result

        url = "https://hashes.com/en/api/search"
        data = {
            'key': self.api_key,
            'hashes[]': [hash_value]
        }

        try:
            response = self.session.post(url, data=data)
            response.raise_for_status()
            result = response.json()

            if result.get('founds'):
                found = result['founds'][0]
                result = HashResult(
                    original_hash=hash_value,
                    plaintext=found.get('plaintext'),
                    algorithm=found.get('algorithm', 'unknown'),
                    salt=found.get('salt')
                )
            else:
                result = HashResult(hash_value, None, 'unknown')
            
            # Stocker le résultat dans le cache
            self._hash_cache[hash_value] = result
            return result
        except requests.RequestException as e:
            print(colored(f"Erreur lors du déchiffrement du hash {hash_value}: {str(e)}", 'red'))
            return None

    def extract_gravatar_hashes(self, users: List[Dict]) -> List[str]:
        """Extract Gravatar hashes from WordPress user avatar URLs"""
        hashes = []
        for user in users:
            if 'avatar_urls' in user:
                for size, url in user['avatar_urls'].items():
                    # Extract hash from Gravatar URL
                    parsed_url = urlparse(url)
                    if 'gravatar.com' in parsed_url.netloc and '/avatar/' in parsed_url.path:
                        hash_match = parsed_url.path.split('/avatar/')[-1].split('?')[0]
                        if hash_match and hash_match not in hashes:
                            hashes.append(hash_match)
        return hashes

    def print_wordpress_users(self, users: List[Dict], decrypt_hashes: bool = False):
        """Print WordPress users information"""
        print(colored("\nUtilisateurs WordPress trouvés:", 'green'))
        print("=" * 50)
        
        for user in users:
            print(f"Nom d'utilisateur: {user.get('username', 'Inconnu')}")
            print(f"Nom affiché: {user.get('name', 'Inconnu')}")
            print(f"ID Utilisateur: {user.get('id', 'Inconnu')}")
            print(f"Rôle: {user.get('roles', ['Inconnu'])[0] if user.get('roles') else 'Inconnu'}")
            
            if 'avatar_urls' in user:
                for url in user['avatar_urls'].values():
                    parsed_url = urlparse(url)
                    if 'gravatar.com' in parsed_url.netloc and '/avatar/' in parsed_url.path:
                        hash_value = parsed_url.path.split('/avatar/')[-1].split('?')[0]
                        print(f"Hash Gravatar: {hash_value}")
                        if decrypt_hashes and self.api_key:
                            result = self.decrypt_hash(hash_value)
                            if result and result.plaintext:
                                print(colored(f"Email déchiffré: {result.plaintext}", 'yellow'))
            print("\n")

    def extract_relevant_exif(self, exif_data) -> Dict:
        """Extract only relevant EXIF data that could reveal identity"""
        relevant_data = {}
        
        # EXIF IFD Tags that might contain personal info
        exif_ifd_tags = {
            piexif.ExifIFD.DateTimeOriginal: "Date originale",
            piexif.ExifIFD.UserComment: "Commentaire utilisateur",
            piexif.ExifIFD.CameraOwnerName: "Nom du propriétaire de l'appareil",
            piexif.ExifIFD.BodySerialNumber: "Numéro de série de l'appareil",
            piexif.ExifIFD.LensMake: "Marque de l'objectif",
            piexif.ExifIFD.LensModel: "Modèle de l'objectif",
            piexif.ExifIFD.LensSerialNumber: "Numéro de série de l'objectif"
        }
        
        # 0th IFD Tags that might contain personal info
        ifd0_tags = {
            piexif.ImageIFD.Make: "Marque de l'appareil",
            piexif.ImageIFD.Model: "Modèle de l'appareil",
            piexif.ImageIFD.Software: "Logiciel",
            piexif.ImageIFD.Copyright: "Droit d'auteur",
            piexif.ImageIFD.Artist: "Artiste"
        }

        try:
            # Check GPS data
            if "GPS" in exif_data and exif_data["GPS"]:
                gps = exif_data["GPS"]
                if piexif.GPSIFD.GPSLatitude in gps and piexif.GPSIFD.GPSLongitude in gps:
                    try:
                        lat = [x[0]/x[1] for x in gps[piexif.GPSIFD.GPSLatitude]]
                        lon = [x[0]/x[1] for x in gps[piexif.GPSIFD.GPSLongitude]]
                        lat_ref = gps[piexif.GPSIFD.GPSLatitudeRef].decode() if piexif.GPSIFD.GPSLatitudeRef in gps else 'N'
                        lon_ref = gps[piexif.GPSIFD.GPSLongitudeRef].decode() if piexif.GPSIFD.GPSLongitudeRef in gps else 'E'
                        
                        lat_decimal = lat[0] + lat[1]/60 + lat[2]/3600
                        lon_decimal = lon[0] + lon[1]/60 + lon[2]/3600
                        
                        if lat_ref == 'S': lat_decimal = -lat_decimal
                        if lon_ref == 'W': lon_decimal = -lon_decimal
                        
                        relevant_data["Localisation GPS"] = f"{lat_decimal:.6f}, {lon_decimal:.6f}"
                    except:
                        pass

            # Extract relevant EXIF IFD data
            if "Exif" in exif_data:
                for tag, label in exif_ifd_tags.items():
                    if tag in exif_data["Exif"] and exif_data["Exif"][tag]:
                        value = exif_data["Exif"][tag]
                        if isinstance(value, bytes):
                            try:
                                value = value.decode()
                            except:
                                continue
                        relevant_data[label] = value

            # Extract relevant 0th IFD data
            if "0th" in exif_data:
                for tag, label in ifd0_tags.items():
                    if tag in exif_data["0th"] and exif_data["0th"][tag]:
                        value = exif_data["0th"][tag]
                        if isinstance(value, bytes):
                            try:
                                value = value.decode()
                            except:
                                continue
                        relevant_data[label] = value

        except Exception as e:
            pass

        return relevant_data

    def analyze_exif(self, domain: str, max_pages: int = 10) -> List[str]:
        """Analyze EXIF data from media files"""
        clean_domain = self.clean_domain(domain)
        results = []
        page = 1
        per_page = 20
        total_pages = None

        print(colored("\nAnalyse des médias...", "cyan"))
        while page <= max_pages:  # Limite à max_pages pages
            url = f"https://{clean_domain}/wp-json/wp/v2/media?page={page}&per_page={per_page}"
            
            try:
                response = requests.get(url, headers=self.base_headers, verify=False)
                if response.status_code != 200:
                    break

                media_items = response.json()
                if not media_items:
                    break

                # Obtenir le nombre total de pages lors de la première requête
                if page == 1 and 'X-WP-TotalPages' in response.headers:
                    total_pages = min(int(response.headers['X-WP-TotalPages']), max_pages)
                    if total_pages == 0:
                        print(colored("Aucun média trouvé.", "yellow"))
                        return results

                with tqdm(total=len(media_items), desc=f"Analyse de la page {page}/{total_pages}", unit="média") as pbar:
                    for item in media_items:
                        media_url = item.get('source_url', '')
                        if not media_url:
                            pbar.update(1)
                            continue

                        try:
                            media_response = requests.get(media_url, headers=self.base_headers, verify=False)
                            if media_response.status_code == 200:
                                image_data = media_response.content
                                try:
                                    exif_dict = piexif.load(image_data)
                                    relevant_data = self.extract_relevant_exif(exif_dict)
                                    if relevant_data and not (len(relevant_data) == 1 and relevant_data.get('Date originale') == '0'):
                                        print(colored(f"\nDonnées EXIF: {media_url}", "green"))
                                        for key, value in relevant_data.items():
                                            print(f"{key}: {value}")
                                        results.append({"url": media_url, "exif": relevant_data})
                                except:
                                    # Essayer d'extraire les métadonnées de l'image directement
                                    if 'media_details' in item and 'image_meta' in item['media_details']:
                                        meta = item['media_details']['image_meta']
                                        if meta and any(meta.values()):
                                            relevant_data = {}
                                            if meta.get('camera'):
                                                relevant_data["Marque de l'appareil"] = meta['camera']
                                            if meta.get('created_timestamp') and meta.get('created_timestamp') != '0':
                                                relevant_data["Date originale"] = meta['created_timestamp']
                                            if meta.get('copyright'):
                                                relevant_data["Droit d'auteur"] = meta['copyright']
                                            if meta.get('credit'):
                                                relevant_data["Artiste"] = meta['credit']
                                            if meta.get('title'):
                                                relevant_data["Titre"] = meta['title']
                                            if relevant_data:
                                                print(colored(f"\nDonnées EXIF: {media_url}", "green"))
                                                for key, value in relevant_data.items():
                                                    print(f"{key}: {value}")
                                                results.append({"url": media_url, "exif": relevant_data})
                        except:
                            pass
                        pbar.update(1)

                page += 1
                
            except Exception as e:
                break

        if not results:
            print(colored("\nAucune donnée EXIF pertinente trouvée.", "yellow"))
        
        return results

    def export_results(self, results: Dict, output_format: str, output_file: Path):
        """Export results to JSON or CSV format"""
        if output_format.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
        elif output_format.lower() == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys() if results else [])
                writer.writeheader()
                writer.writerows(results)

async def process_domains(domains: List[str], args) -> Tuple[Set[str], List[Dict], List[Dict]]:
    analyzer = WordPressAnalyzer(args.api_key)
    all_hashes = set()
    all_users = []
    all_exif = []
    
    connector = aiohttp.TCPConnector(limit=100, force_close=True)
    timeout = aiohttp.ClientTimeout(total=5)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [(domain, analyzer.get_wordpress_users_async(domain, session, args.bypass)) 
                for domain in domains]
        
        if not args.raw:
            print("\nAnalyse des domaines en cours...")
        
        for domain, future in tqdm(tasks, disable=args.raw, desc="Traitement des domaines", unit="domaine"):
            try:
                users = await future
                
                if users:
                    all_users.extend(users)
                    
                    for user in users:
                        if 'avatar_urls' in user:
                            for url in user['avatar_urls'].values():
                                parsed_url = urlparse(url)
                                if 'gravatar.com' in parsed_url.netloc and '/avatar/' in parsed_url.path:
                                    hash_value = parsed_url.path.split('/avatar/')[-1].split('?')[0]
                                    all_hashes.add(hash_value)

                    if args.domain or (not args.raw and args.verbose):
                        print(colored(f"\nUtilisateurs trouvés pour le domaine: {domain}", 'green'))
                        analyzer.print_wordpress_users(users, decrypt_hashes=True)

                    if args.exif:
                        exif_results = analyzer.analyze_exif(domain, max_pages=10)
                        if exif_results:
                            all_exif.extend([result for result in exif_results 
                                           if not (len(result['exif']) == 1 and result['exif'].get('Date originale') == '0')])
            except Exception:
                if args.verbose:
                    print(colored(f"\nErreur lors de l'analyse de {domain}", "red"))
                continue

    if not args.raw and all_hashes:
        print(colored(f"\nTotal des hashes uniques trouvés: {len(all_hashes)}", "green"))
        print(colored("\nHashes trouvés:", "cyan"))
        for hash_value in sorted(all_hashes):
            print(hash_value)
    
    return all_hashes, all_users, all_exif

def print_banner():
    banner = """
██╗    ██╗██████╗ ██╗███╗   ██╗████████╗
██║    ██║██╔══██╗██║████╗  ██║╚══██╔══╝
██║ █╗ ██║██████╔╝██║██╔██╗ ██║   ██║   
██║███╗██║██╔═══╝ ██║██║╚██╗██║   ██║   
╚███╔███╔╝██║     ██║██║ ╚████║   ██║   
 ╚══╝╚══╝ ╚═╝     ╚═╝╚═╝  ╚═══╝   ╚═╝   
"""
    contact = """
╔══════════════════════════════════════════════════════════════╗
║  @RedSecurityfr - red-security.fr - osint-opsec.fr           ║
║                                                              ║
║  Rejoignez la communauté OSINT:                              ║
║  https://discord.com/invite/rPkY5jaTfF                       ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(colored(banner, 'red', attrs=['bold']))
    print(colored(contact, 'yellow', attrs=['bold']))

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Analyseur de Sites WordPress')
    parser.add_argument('-d', '--domain', help='Domaine unique à analyser')
    parser.add_argument('-l', '--list', help='Fichier contenant une liste de domaines')
    parser.add_argument('-e', '--exif', action='store_true', help='Activer l\'analyse EXIF')
    parser.add_argument('-b', '--bypass', action='store_true', help='Activer le contournement de limite')
    parser.add_argument('--json', help='Exporter les résultats en JSON')
    parser.add_argument('--raw', action='store_true', help='Afficher uniquement les hashes, un par ligne')
    parser.add_argument('--verbose', action='store_true', help='Afficher les messages d\'erreur et les détails')
    parser.add_argument('--api-key', help='Clé API Hashes.com (optionnel)')

    args = parser.parse_args()

    if not args.domain and not args.list:
        parser.error("L'option -d/--domain ou -l/--list doit être spécifiée")

    domains = []
    if args.domain:
        domains.append(args.domain)
    elif args.list:
        with open(args.list) as f:
            domains = [line.strip() for line in f if line.strip()]

    all_hashes, users, exif_data = asyncio.run(process_domains(domains, args))

    if args.raw:
        for hash_value in sorted(all_hashes):
            print(hash_value)

    if args.json:
        with open(args.json, 'w') as f:
            json.dump({
                'hashes': list(all_hashes),
                'users': users,
                'exif_data': exif_data
            }, f, indent=4)
        if args.verbose or args.domain:
            print(colored(f"\nRésultats exportés vers {args.json}", 'green'))

if __name__ == '__main__':
    main()
