# Herramienta de Análisis de Dependencias

Una herramienta para analizar dependencias de código e identificar vulnerabilidades utilizando una base de datos PostgreSQL.

## Características

-   **Soporte Multi-Lenguaje**: Escanea dependencias para:
    -   Python (PyPI)
    -   Java (Maven)
    -   PHP (Packagist)
    -   JavaScript/TypeScript (NPM)
    -   Golang (Go Modules)
    -   .NET (NuGet)
-   **Resolución Automática de Versiones**: Resuelve automáticamente versiones "desconocidas" consultando los registros oficiales de paquetes (PyPI, Maven Central, NPM, etc.).
-   **Coincidencia de Vulnerabilidades**: Verifica las dependencias contra una base de datos de vulnerabilidades PostgreSQL (NIST CPEs).
    -   Maneja coincidencias exactas.
    -   Maneja nombres con ámbito (ej. `com.example/lib` -> `lib`).
    -   Utiliza `package_aliases` para la resolución de nombres canónicos.
-   **Identificación del Fabricante (Vendor)**:
    -   Recupera el fabricante de la base de datos.
    -   Fallback: Extrae el fabricante/namespace de las URLs del Paquete (PURL) si no se encuentra en la BD.
-   **Integración con Git**: Clona, escanea y limpia automáticamente repositorios Git remotos.
-   **Sanitización y Deduplicación**:
    -   Elimina caracteres especiales (como `@`) de los nombres y fabricantes en la salida.
    -   Deduplica dependencias para asegurar una salida limpia.
-   **Salida JSON**: Genera un informe JSON detallado.

## Arquitectura

Este proyecto sigue la **Arquitectura Hexagonal** (Puertos y Adaptadores):

-   **Dominio** (`src/domain`): Lógica de negocio central y modelos (`Dependency`, `Vulnerability`, `ScanResult`). Define interfaces (`ports.py`).
-   **Adaptadores** (`src/adapters`): Implementaciones concretas.
    -   `SyftScanner`: Envuelve `syft` para escanear código y resolver versiones.
    -   `PostgresRepository`: Conecta a PostgreSQL para encontrar vulnerabilidades.
    -   `GitProvider`: Maneja el clonado y limpieza.
-   **Aplicación** (`src/application`): Orquesta el flujo de análisis (`DependencyAnalysisService`).
-   **Puntos de Entrada** (`src/entrypoints`): Interfaz de línea de comandos (`cli.py`).

## Prerrequisitos

-   **Python 3.8+**
-   **Syft**: Debe estar instalado y disponible en el PATH de tu sistema.
    -   [Guía de Instalación](https://github.com/anchore/syft#installation)
-   **PostgreSQL**: Una base de datos poblada con datos de vulnerabilidades (tablas: `products`, `vulnerabilities`, `vulnerability_product_map`, `package_aliases`).
-   **Git**: Para clonar repositorios.

## Instalación

1.  Clona este repositorio.
2.  Crea un entorno virtual:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  Instala las dependencias:
    ```bash
    pip install -r requirements.txt
    # O
    pip install sqlalchemy psycopg2-binary python-dotenv
    ```

## Configuración

Crea un archivo `.env` en la raíz del proyecto con las credenciales de tu base de datos:

```ini
DB_USER=tu_usuario
DB_PASSWORD=tu_contraseña
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnerabilities
```

## Uso

### Escanear un Repositorio Remoto

```bash
./venv/bin/python src/entrypoints/cli.py --repo-url https://github.com/usuario/repo --output resultados.json
```

### Escanear un Directorio Local

```bash
./venv/bin/python src/entrypoints/cli.py --path /ruta/al/proyecto/local --output resultados.json
```

### Formato de Salida

La herramienta genera un archivo JSON con la siguiente estructura:

```json
[
  {
    "dependency": {
      "name": "nombre-dependencia",
      "version": "1.2.3",
      "type": "npm",
      "purl": "pkg:npm/nombre-dependencia@1.2.3"
    },
    "vulnerabilities": [
      {
        "cve_id": "CVE-2023-XXXX",
        "description": "Descripción de la vulnerabilidad...",
        "cvss_v31_score": 9.8,
        "cvss_v31_severity": "CRITICAL"
      }
    ],
    "vendor": "nombre-fabricante"
  }
]
```

## Desarrollo

-   **Ejecutar Pruebas**: Crea scripts de verificación en el directorio raíz para probar adaptadores específicos.
-   **Agregar Lenguajes**: Actualiza `SyftScanner._get_latest_version` en `src/adapters/scanner/syft_scanner.py`.
