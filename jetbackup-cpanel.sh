#!/bin/bash
# Configuración global
set -euo pipefail
IFS=$'\n\t'

# Funciones de utilidad
mostrar_error() {
	echo ""
	echo "❌ Error: $1"
	exit 1
}

mostrar_error_con_ayuda() {
	echo ""
	echo "❌ Error: $1"
	echo "
Uso del script:
$0 ARCHIVO_JETBACKUP5 [CARPETA_DESTINO]

ARCHIVO_JETBACKUP5 = Archivo de respaldo de JetBackup 5
CARPETA_DESTINO   = Carpeta opcional para el respaldo de cPanel,
                    por defecto /home/ si eres root, sino ~/

Ejemplo: 
$0 /home/download_jb5user_1663238955_28117.tar.gz
"
	exit 1
}

# Función para descomprimir archivos tar
descomprimir_tar() {
	local archivo_origen="$1"
	local directorio_destino="$2"
	
	echo "📦 Descomprimiendo archivo tar..."
	tar -xf "$archivo_origen" -C "$directorio_destino"
	local codigo_error=$?
	
	if [[ $codigo_error -gt 0 ]]; then
		mostrar_error "No se pudo descomprimir el archivo '$archivo_origen'"
	fi
}

# Función para extraer archivos comprimidos
extraer_archivos() {
	local ruta_archivo="$1"
	echo "🗜️  Extrayendo archivos comprimidos..."
	gunzip $ruta_archivo
	local codigo_error=$?
	
	if [[ $codigo_error -gt 0 ]]; then
		mostrar_error "No se pudieron extraer los archivos"
	fi
}

# Función para mover directorios
mover_directorio() {
	local origen="$1"
	local destino="$2"
	echo "📁 Moviendo directorio '$origen'"
	
	mv $origen "$destino"
	local codigo_error=$?
	
	if [[ $codigo_error -gt 0 ]]; then
		mostrar_error "Ocurrió un error al mover el directorio"
	fi
}

# Función para crear archivo final
crear_archivo_final() {
	local nombre_archivo="$1"
	echo "📦 Creando archivo final '$directorio_destino/$nombre_archivo'"
	
	# Eliminar archivo existente si existe
	if [[ -f "$directorio_destino/$nombre_archivo" ]]; then
		rm "$directorio_destino/$nombre_archivo"
	fi
	
	cd "$directorio_temporal" || mostrar_error "No se pudo cambiar al directorio '$directorio_temporal'"
	tar -czf "$directorio_destino/$nombre_archivo" "cpmove-$nombre_cuenta" >/dev/null 2>&1
	local codigo_error=$?
	
	if [[ $codigo_error != 0 ]]; then
		mostrar_error "No se pudo crear el archivo tar"
	fi
}

# Función para crear cuentas FTP
configurar_cuentas_ftp() {
	local ruta_directorio="$1"
	local ruta_configuracion="$2"
	local directorio_home="$( cat "$ruta_configuracion/meta/homedir_paths" )"
	local usuario="$( ls "$ruta_configuracion/cp/")"
	
	echo "🔐 Configurando cuentas FTP..."
	
	for archivo in $(ls -1 "$ruta_directorio" | grep -iE "\.acct$"); do
		local nombre_usuario="$(grep -Po '(?<=name: )(\w\D+)' "$ruta_directorio/$archivo")"
		local contrasena="$(grep -Po '(?<=password: )([A-Za-z0-9!@#$%^&*,()\/\\.])+' "$ruta_directorio/$archivo")"
		local ruta_web="$(grep -Po '(?<=path: )([A-Za-z0-9\/_.-]+)' "$ruta_directorio/$archivo")"
		
		echo "  Creando cuenta FTP '$nombre_usuario'"
		printf "%s:%s:0:0:%s:%s/%s:/bin/ftpsh" "$nombre_usuario" "$contrasena" "$usuario" "$directorio_home" "$ruta_web" >> "$directorio_cpanel/proftpdpasswd"
	done
}

# Función para crear archivo MySQL
generar_archivo_mysql() {
	local ruta_directorio="$1"
	local ruta_sql="$2"
	
	echo "🗄️  Generando configuración de bases de datos..."
	
	for archivo in $(ls -1 "$ruta_directorio" | grep -iE "\.user$"); do
		local nombre_usuario="$(grep -Po '(?<=name: )([a-zA-Z0-9!@#$%^&*(\)\_\.-]+)' "$ruta_directorio/$archivo")"
		local base_datos="$(grep -Po '(?<=database `)([_a-zA-Z0-9]+)' "$ruta_directorio/$archivo")"
		local usuario="$(grep -Po '(?<=name: )([a-zA-Z0-9!#$%^&*(\)\_\.]+)' "$ruta_directorio/$archivo")"
		local dominio="$(echo "$nombre_usuario" | grep -Po '(?<=@)(.*)$')"
		local contrasena="$(grep -Po '(?<=password: )([a-zA-Z0-9*]+)' "$ruta_directorio/$archivo")"
		local permisos="$(grep -Po '(?<=:)[A-Z ,]+$' "$ruta_directorio/$archivo")"
		
		echo "  Creando BD '$base_datos' y usuario '$usuario'"
		
		echo "GRANT USAGE ON *.* TO '$usuario'@'$dominio' IDENTIFIED BY PASSWORD '$contrasena';" >> "$ruta_sql"
		echo "GRANT$permisos ON \`$base_datos\`.* TO '$usuario'@'$dominio';" >> "$ruta_sql"
	done
}

# Función para crear cuentas de correo
configurar_cuentas_correo() {
	local ruta_correo_origen="$1"
	local ruta_correo_destino="$2"
	
	echo "📧 Configurando cuentas de correo electrónico..."
	
	for archivo_json in $(ls -1 "$ruta_correo_origen" | grep -iE "\.conf$"); do
		local archivo_completo="$ruta_correo_origen/$archivo_json"
		local usuario_correo="$(jq -r '.account' "$archivo_completo" | base64 --decode)"
		local dominio_correo="$(jq -r '.domain' "$archivo_completo" | base64 --decode)"
		local contrasena_correo="$(jq -r '.password' "$archivo_completo" | base64 --decode)"
		
		echo "  Creando cuenta de correo para '$usuario_correo@$dominio_correo'"
		echo "${usuario_correo}:${contrasena_correo}:::::::" >>"$ruta_correo_destino/${dominio_correo}/shadow"
	done
}

# Función para crear dominios
configurar_dominios() {
	local ruta_directorio="$1"
	local ruta_configuracion="$2"
	
	echo "🌐 Configurando dominios..."
	
	# Buscar dominio principal
	local dominio_principal=""
	for archivo_json in "$ruta_directorio"/*.conf; do
		local dominio="$(jq -r '.domain' "$archivo_json" | base64 --decode)"
		local tipo="$(jq -r '.type' "$archivo_json" | base64 --decode)"
		if [[ "$tipo" -eq 1 ]]; then
			dominio_principal="$dominio"
		fi
	done
	
	if [[ -z "$dominio_principal" ]]; then
		mostrar_error "No se pudo encontrar el dominio principal de la cuenta '$nombre_cuenta'"
	fi
	
	# Configurar subdominios del dominio principal
	echo -n "" >"$ruta_configuracion"/sds
	echo -n "" >"$ruta_configuracion"/sds2
	
	for archivo_json in "$ruta_directorio"/*.conf; do
		local dominio="$(jq -r '.domain' "$archivo_json" | base64 --decode)"
		local tipo="$(jq -r '.type' "$archivo_json" | base64 --decode)"
		
		if [[ "$tipo" -eq 3 && "$dominio" == *.$dominio_principal ]]; then
			echo "  Agregando subdominio '$dominio'"
			echo "${dominio/./_}"         >>"$ruta_configuracion"/sds
			echo "${dominio/./_}=$dominio" >>"$ruta_configuracion"/sds2
		fi
	done
	
	# Configurar dominios adicionales y estacionados
	echo -n "" >"$ruta_configuracion"/addons
	echo -n "" >"$ruta_configuracion"/pds
	
	for archivo_json in "$ruta_directorio"/*.conf; do
		local dominio="$(jq -r '.domain' "$archivo_json" | base64 --decode)"
		local tipo="$(jq -r '.type' "$archivo_json" | base64 --decode)"
		
		case $tipo in
			1) # Dominio principal - ignorar
				;;
			2) # Dominio adicional
				echo "  Agregando dominio adicional '$dominio'"
				echo "$dominio=${dominio/./_}.$dominio_principal" >>"$ruta_configuracion"/addons
				echo "${dominio/./_}.$dominio_principal"         >>"$ruta_configuracion"/sds
				echo "${dominio/./_}.$dominio_principal=$dominio" >>"$ruta_configuracion"/sds2
				;;
			3) # Subdominio - ya procesado
				;;
			4) # Dominio estacionado
				echo "$dominio" >>"$ruta_configuracion"/pds
				;;
			*)
				mostrar_error "El dominio '$dominio' tiene un tipo desconocido '$tipo'"
				;;
		esac
	done
	
	# Configurar subdominios que NO son del dominio principal
	for archivo_json in "$ruta_directorio"/*.conf; do
		local dominio="$(jq -r '.domain' "$archivo_json" | base64 --decode)"
		local tipo="$(jq -r '.type' "$archivo_json" | base64 --decode)"
		
		if [[ "$tipo" -eq 3 && ! "$dominio" == *.$dominio_principal ]]; then
			echo "  Agregando subdominio independiente '$dominio'"
			echo "${dominio/./_}"         >>"$ruta_configuracion"/sds
			echo "${dominio/./_}=$dominio" >>"$ruta_configuracion"/sds2
		fi
	done
}

# Función para crear certificados SSL
configurar_certificados_ssl() {
	local ruta_directorio="$1"
	local ruta_configuracion="$2"
	
	echo "🔒 Configurando certificados SSL..."
	
	# Indicar que la cuenta usará el Gestor de Almacenamiento SSL de WHM
	touch "$ruta_configuracion"/has_sslstorage
	
	# El código comentado a continuación parece innecesario con la línea anterior
	return
}

# Función para crear zonas DNS
configurar_zonas_dns() {
	local ruta_directorio="$1"
	local ruta_configuracion="$2"
	
	echo "🌍 Configurando zonas DNS..."
	
	for archivo in "$ruta_directorio"/*.zone; do
		local nombre_archivo="${archivo##*/}"
		local archivo_destino="$ruta_configuracion/dnszones/${nombre_archivo%.*}.db"
		
		echo "  Creando '$archivo_destino'"
		mv "$archivo" "$archivo_destino"
		local codigo_error=$?
		
		if [[ $codigo_error -gt 0 ]]; then
			mostrar_error "Ocurrió un error al procesar la zona DNS"
		fi
	done
}

# Función para determinar directorio temporal
seleccionar_directorio_temporal() {
	local archivo="$1"
	local espacio_requerido=$(du --block-size=1 "$archivo" | cut -f1)
	local espacio_tmp=$(df --block-size=1 --output=avail /tmp | tail -n1)
	
	if [[ $(( espacio_requerido * 10 )) -lt $espacio_tmp ]]; then
		echo "/tmp"
	elif [[ $(( espacio_requerido * 2 )) -gt $espacio_tmp ]]; then
		echo "~"
	else
		echo "Verificando tamaño descomprimido..."
		local tamano_descomprimido=$(zcat "$archivo" | wc -c)
		if [[ $(( tamano_descomprimido * 2 )) -lt $espacio_tmp ]]; then
			echo "/tmp"
		else
			echo "~"
		fi
	fi
}

# Función principal de limpieza
limpiar_temporal() {
	if [[ -n "${directorio_temporal:-}" && -d "$directorio_temporal" ]]; then
		echo "🧹 Limpiando directorio temporal..."
		rm -rf "$directorio_temporal"
	fi
}

# Configurar trap para limpieza automática
trap limpiar_temporal EXIT INT TERM

# Procesar argumentos
archivo_origen="$1"
directorio_destino="${2:-}"

# Validaciones iniciales
if [[ ! -f "$archivo_origen" ]]; then
	mostrar_error_con_ayuda "Archivo inválido proporcionado"
fi

if [[ "$directorio_destino" == "/" ]]; then
	mostrar_error_con_ayuda "Error: No uses la carpeta raíz como destino"
fi

# Establecer directorio destino por defecto
if [[ -z "$directorio_destino" ]]; then
	if [[ "$(whoami)" == "root" ]]; then
		directorio_destino="/home"
	else
		directorio_destino="~"
	fi
fi

# Extraer nombre de cuenta
nombre_cuenta="$(echo "${archivo_origen##*/}" | cut -d_ -f2)"

# Determinar directorio temporal
directorio_tmp_base=$(seleccionar_directorio_temporal "$archivo_origen")
directorio_temporal="$(mktemp --directory --tmpdir=$directorio_tmp_base "tmp_jb5_$nombre_cuenta.XXXXXXXX")"

echo "📁 Archivo de respaldo encontrado: '$archivo_origen'"
echo "👤 Cuenta identificada: '$nombre_cuenta'"
echo "📂 Creando directorio temporal: '$directorio_temporal'"

# Crear directorio temporal
mkdir -p "$directorio_temporal" || mostrar_error_con_ayuda "Error al crear directorio de destino"
[[ ! -d "$directorio_temporal" ]] && mostrar_error_con_ayuda "Error en directorio de destino"

echo "📦 Descomprimiendo '$archivo_origen' en '$directorio_temporal'"
descomprimir_tar "$archivo_origen" "$directorio_temporal"

if [[ ! -d "$directorio_temporal/backup" ]]; then
	mostrar_error "Directorio de respaldo JetBackup5 '$directorio_temporal/backup' no encontrado"
fi

directorio_cpanel="$directorio_temporal/cpmove-$nombre_cuenta"
directorio_jb5="$directorio_temporal/backup"

echo "🔄 Convirtiendo cuenta '$nombre_cuenta'"
echo "📂 Directorio de trabajo: '$directorio_cpanel'"

# Procesar configuración
if [[ ! -d "$directorio_jb5/config" ]]; then
	mostrar_error_con_ayuda "El respaldo no contiene el directorio de configuración"
else
	mover_directorio "$directorio_jb5/config" "$directorio_cpanel/"
fi

# Procesar directorio home
if [[ -d "$directorio_jb5/homedir" ]]; then
	if [[ ! -d "$directorio_cpanel/homedir" ]]; then
		mover_directorio "$directorio_jb5/homedir" "$directorio_cpanel"
	else
		echo "📁 Sincronizando directorio home..."
		rsync -ar "$directorio_jb5/homedir" "$directorio_cpanel"
	fi
fi

# Procesar bases de datos
if [[ -d "$directorio_jb5/database" ]]; then
	mover_directorio "$directorio_jb5/database/*" "$directorio_cpanel/mysql"
	extraer_archivos "$directorio_cpanel/mysql/*"
fi

# Procesar usuarios de base de datos
if [[ -d "$directorio_jb5/database_user" ]]; then
	generar_archivo_mysql "$directorio_jb5/database_user" "$directorio_cpanel/mysql.sql"
fi

# Procesar correo electrónico
if [[ -d "$directorio_jb5/email" ]]; then
	mover_directorio "$directorio_jb5/email" "$directorio_cpanel/homedir/mail"
	if [[ -d "$directorio_jb5/jetbackup.configs/email" ]]; then
		configurar_cuentas_correo "$directorio_jb5/jetbackup.configs/email" "$directorio_cpanel/homedir/etc"
	fi
fi

# Procesar FTP
if [[ -d "$directorio_jb5/ftp" ]]; then
	configurar_cuentas_ftp "$directorio_jb5/ftp" "$directorio_cpanel"
fi

# Procesar dominios
if [[ -d "$directorio_jb5/jetbackup.configs/domain" ]]; then
	configurar_dominios "$directorio_jb5/jetbackup.configs/domain" "$directorio_cpanel"
	configurar_certificados_ssl "$directorio_jb5/jetbackup.configs/domain" "$directorio_cpanel"
fi

# Procesar zonas DNS
if [[ -d "$directorio_jb5/domain" ]]; then
	configurar_zonas_dns "$directorio_jb5/domain" "$directorio_cpanel"
fi

echo "🎯 Creando archivo final de respaldo cPanel..."
crear_archivo_final "cpmove-$nombre_cuenta.tar.gz"

echo "✅ ¡Conversión completada exitosamente!"
echo -e "📦 Tu respaldo de cPanel está en:\n$directorio_destino/cpmove-$nombre_cuenta.tar.gz"

