# Validador de Credenciales SSH/Telnet

## ⚠️ AVISO ÉTICO Y LEGAL ⚠️
**Esta herramienta es EXCLUSIVAMENTE para fines académicos y educativos.**  
El uso debe ser responsable, ético y legal. El usuario asume toda la responsabilidad legal ante cualquier uso indebido de esta aplicación.

## Descripción

Esta aplicación en Python permite realizar auditorías y validaciones de credenciales SSH y Telnet utilizando la API de Shodan. El script está diseñado con fines educativos para comprender mejor los aspectos de seguridad relacionados con estos protocolos de comunicación.

## Funcionalidades

### Funcionalidades Básicas:
- Búsqueda en Shodan API para identificar IPs con servicios SSH (puerto 22) y Telnet (puerto 23) expuestos en países de Latinoamérica.
- Identificación de servicios activos en puertos no convencionales.
- Carga y gestión de listas independientes de IPs, usuarios y contraseñas desde archivos .txt.
- Validación efectiva de la apertura de los puertos mediante conexiones reales.

### Funcionalidades Avanzadas:
- Validación masiva automatizada de credenciales mediante SSH (paramiko) y Telnet (telnetlib).
- Generación de reportes estadísticos detallados de IPs accesibles.
- Manejo robusto de errores (autenticación fallida, conexión fallida, timeout, etc.).
- Rotación de múltiples claves API de Shodan para gestionar límites de créditos.
- Generación automática de archivos y logs con credenciales válidas encontradas.

## Requisitos

### Requisitos del Sistema:
- Python 3.6+
- Sistema Operativo: Compatible con Kali Linux y Windows 11

### Bibliotecas Requeridas:
```
shodan
paramiko
telnetlib
```

## Instalación

1. Clona este repositorio o descarga el archivo fuente:
```bash
git clone https://github.com/tu_usuario/ssh-telnet-validator.git
cd ssh-telnet-validator
```

2. Instala las dependencias necesarias:
```bash
pip install -r requirements.txt
```

El archivo `requirements.txt` debe contener:
```
paramiko==2.12.0
shodan==1.28.0
```

## Configuración

Antes de utilizar la herramienta, necesitas configurar algunos archivos:

1. **Archivo de claves API** (`api_keys.txt`):
   - Crea un archivo con tus claves API de Shodan, una por línea
   - Ejemplo:
     ```
     Tu_Clave_API_1
     Tu_Clave_API_2
     ```

2. **Archivo de usuarios** (`users.txt`):
   - Crea un archivo con los nombres de usuario a probar, uno por línea
   - Ejemplo:
     ```
     admin
     root
     user
     ```

3. **Archivo de contraseñas** (`passwords.txt`):
   - Crea un archivo con las contraseñas a probar, una por línea
   - Ejemplo:
     ```
     admin
     password
     123456
     ```

4. **Archivo de IPs opcional** (`ips.txt`):
   - Si deseas probar IPs específicas además de las encontradas con Shodan
   - Ejemplo:
     ```
     192.168.1.1
     10.0.0.1
     ```

## Uso

### Uso Básico:
```bash
python ssh_telnet_validator.py -k api_keys.txt -u users.txt -p passwords.txt
```

### Opciones Disponibles:
```
Argumentos obligatorios:
  -k, --api-keys-file    Archivo con claves API de Shodan (una por línea)
  -u, --username-file    Archivo con nombres de usuario (uno por línea)
  -p, --password-file    Archivo con contraseñas (una por línea)

Argumentos opcionales:
  -i, --ip-file          Archivo con IPs adicionales a probar
  -c, --countries        Países específicos de Latinoamérica a buscar
  -m, --max-results      Número máximo de resultados a obtener de Shodan (default: 100)
  --ssh-port             Puerto SSH personalizado (default: 22)
  --telnet-port          Puerto Telnet personalizado (default: 23)
  --skip-ssh             Omitir la búsqueda y validación de SSH
  --skip-telnet          Omitir la búsqueda y validación de Telnet
  --skip-port-check      Omitir la verificación de puerto abierto
  --validate-credentials Realizar validación de credenciales
  --timeout              Timeout para conexiones en segundos (default: 5)
  --threads              Número de hilos para validación paralela (default: 10)
  --max-cred-attempts    Máximo de combinaciones de credenciales a probar (default: 50)
  --output-creds         Archivo para guardar credenciales válidas (default: valid_credentials.json)
  --output-report        Archivo para guardar el informe (default: scan_report.json)
```

### Ejemplos de Uso:

1. **Búsqueda básica en todos los países de Latinoamérica**:
```bash
python ssh_telnet_validator.py -k api_keys.txt -u users.txt -p passwords.txt
```

2. **Búsqueda en países específicos**:
```bash
python ssh_telnet_validator.py -k api_keys.txt -u users.txt -p passwords.txt -c Colombia Mexico
```

3. **Búsqueda con validación de credenciales**:
```bash
python ssh_telnet_validator.py -k api_keys.txt -u users.txt -p passwords.txt --validate-credentials
```

4. **Búsqueda solo de servicios SSH**:
```bash
python ssh_telnet_validator.py -k api_keys.txt -u users.txt -p passwords.txt --skip-telnet
```

5. **Aumentar el número de hilos para validación más rápida**:
```bash
python ssh_telnet_validator.py -k api_keys.txt -u users.txt -p passwords.txt --validate-credentials --threads 20
```

## Estructura de Archivos de Salida

### Credenciales Válidas (JSON):
```json
[
  {
    "ip": "192.168.1.1",
    "port": 22,
    "protocol": "SSH",
    "username": "admin",
    "password": "password123",
    "timestamp": "2024-04-01T12:34:56"
  },
  ...
]
```

### Reportes Estadísticos (JSON):
```json
{
  "timestamp": "2024-04-01T12:34:56",
  "scan_info": {
    "ssh_enabled": true,
    "telnet_enabled": true,
    "credential_validation": true,
    "port_check_enabled": true
  },
  "ssh_stats": {
    "port_distribution": {
      "total": 100,
      "ports": {
        "22": {"count": 80, "percentage": 80.0},
        "2222": {"count": 20, "percentage": 20.0}
      }
    },
    "country_distribution": {
      "total": 100,
      "countries": {
        "Colombia": {"count": 30, "percentage": 30.0},
        "Mexico": {"count": 45, "percentage": 45.0},
        "Brazil": {"count": 25, "percentage": 25.0}
      }
    }
  },
  "telnet_stats": { ... },
  "validation_stats": {
    "total_ips": 200,
    "accessible_ips": 150,
    "accessible_percentage": 75.0,
    "valid_credentials": 35,
    "success_rate": 23.3
  }
}
```

## Limitaciones y Consideraciones

### Limitaciones Técnicas:
- El consumo de créditos de Shodan API puede limitar la cantidad de búsquedas posibles.
- La velocidad de validación depende de la latencia de red y del número de hilos configurados.
- Algunos proveedores de servicios pueden bloquear conexiones múltiples desde una misma IP.

### Consideraciones de Uso:
- Para evitar consumo excesivo de créditos en Shodan, configure adecuadamente el parámetro `--max-results`.
- Utilice la opción `--max-cred-attempts` para limitar el número de intentos de autenticación por servicio.
- La rotación de claves API de Shodan permite maximizar los resultados obtenidos.

## Solución de Problemas

### Errores Comunes:

1. **Error de API Key:**
   - Mensaje: "Error en la API de Shodan: No API key provided"
   - Solución: Verifique que el archivo de claves API contenga al menos una clave válida.

2. **Timeout en Conexiones:**
   - Mensaje: "Timeout en conexión SSH/Telnet"
   - Solución: Aumente el valor del parámetro `--timeout` o verifique su conexión a internet.

3. **Archivos No Encontrados:**
   - Mensaje: "Archivo no encontrado: [nombre_archivo]"
   - Solución: Verifique las rutas de los archivos proporcionados.


## Licencia

Este proyecto es exclusivamente para fines educativos y académicos. No se proporciona ninguna garantía de ningún tipo.

---

**Autor:** Juan Jose Hurtado Mejia  
**Fecha:** 07 de Abril 2024
