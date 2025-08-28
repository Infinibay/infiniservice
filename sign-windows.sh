#!/bin/bash

# Script para firmar el ejecutable de Windows desde Linux
# Requiere: osslsigncode y un certificado PFX

set -e

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Rutas
EXECUTABLE="/opt/infinibay/infiniservice/binaries/windows/infiniservice.exe"
SIGNED_EXECUTABLE="/opt/infinibay/infiniservice/binaries/windows/infiniservice-signed.exe"

# Verificar que el ejecutable existe
if [ ! -f "$EXECUTABLE" ]; then
    echo -e "${RED}Error: No se encuentra el ejecutable en $EXECUTABLE${NC}"
    exit 1
fi

# Verificar que osslsigncode está instalado
if ! command -v osslsigncode &> /dev/null; then
    echo -e "${YELLOW}osslsigncode no está instalado. Instalando...${NC}"
    sudo apt-get update && sudo apt-get install -y osslsigncode
fi

# Opciones de firma
echo -e "${GREEN}=== Firma Digital de infiniservice.exe ===${NC}"
echo ""
echo "Opciones:"
echo "1) Usar certificado autofirmado (solo para pruebas)"
echo "2) Usar certificado PFX existente"
echo "3) Omitir firma"
echo ""
read -p "Selecciona una opción [1-3]: " option

case $option in
    1)
        # Crear certificado autofirmado para pruebas
        echo -e "${YELLOW}Creando certificado autofirmado...${NC}"
        
        # Generar clave privada
        openssl genrsa -out infinibay.key 2048
        
        # Generar certificado autofirmado
        openssl req -new -x509 -key infinibay.key -out infinibay.crt -days 365 \
            -subj "/C=US/ST=State/L=City/O=Infinibay/CN=Infinibay Code Signing"
        
        # Convertir a PFX
        openssl pkcs12 -export -out infinibay.pfx -inkey infinibay.key -in infinibay.crt \
            -passout pass:infinibay
        
        PFX_FILE="infinibay.pfx"
        PFX_PASSWORD="infinibay"
        
        echo -e "${YELLOW}⚠ ADVERTENCIA: Certificado autofirmado creado. NO usar en producción.${NC}"
        ;;
        
    2)
        # Usar certificado existente
        read -p "Ruta al archivo PFX: " PFX_FILE
        read -s -p "Contraseña del PFX: " PFX_PASSWORD
        echo ""
        
        if [ ! -f "$PFX_FILE" ]; then
            echo -e "${RED}Error: No se encuentra el archivo PFX${NC}"
            exit 1
        fi
        ;;
        
    3)
        echo -e "${YELLOW}Firma omitida${NC}"
        exit 0
        ;;
        
    *)
        echo -e "${RED}Opción inválida${NC}"
        exit 1
        ;;
esac

# Firmar el ejecutable
echo -e "${GREEN}Firmando ejecutable...${NC}"

osslsigncode sign \
    -pkcs12 "$PFX_FILE" \
    -pass "$PFX_PASSWORD" \
    -n "InfiniService" \
    -i "https://infinibay.com" \
    -t "http://timestamp.digicert.com" \
    -in "$EXECUTABLE" \
    -out "$SIGNED_EXECUTABLE"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Ejecutable firmado exitosamente${NC}"
    echo -e "${GREEN}  Original: $EXECUTABLE${NC}"
    echo -e "${GREEN}  Firmado:  $SIGNED_EXECUTABLE${NC}"
    
    # Verificar la firma
    echo ""
    echo -e "${GREEN}Verificando firma...${NC}"
    osslsigncode verify "$SIGNED_EXECUTABLE"
    
    # Reemplazar el original con el firmado
    read -p "¿Reemplazar el ejecutable original con el firmado? [y/N]: " replace
    if [[ $replace =~ ^[Yy]$ ]]; then
        cp "$SIGNED_EXECUTABLE" "$EXECUTABLE"
        echo -e "${GREEN}✓ Ejecutable original reemplazado${NC}"
    fi
    
    # Limpiar archivos temporales si se creó certificado autofirmado
    if [ "$option" = "1" ]; then
        rm -f infinibay.key infinibay.crt infinibay.pfx
        echo -e "${GREEN}✓ Archivos temporales eliminados${NC}"
    fi
else
    echo -e "${RED}Error al firmar el ejecutable${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=== Proceso completado ===${NC}"
echo ""
echo "Notas importantes:"
echo "- Un certificado autofirmado NO eliminará las advertencias de Windows"
echo "- Para eliminar advertencias necesitas un certificado de una CA reconocida"
echo "- Aún con firma, pueden ocurrir falsos positivos de antivirus"
echo "- Reporta falsos positivos en: https://www.microsoft.com/wdsi/filesubmission"