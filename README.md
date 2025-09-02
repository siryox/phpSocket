🚀 Servidor WebSocket Asincrónico en PHP📝 
Descripción del Proyecto
  Este proyecto es un servidor WebSocket seguro (WSS) desarrollado en PHP. Su objetivo principal es gestionar múltiples conexiones de clientes de forma asincrónica y no bloqueante. El servidor actúa como un intermediario entre los clientes y una API REST, ofreciendo dos funcionalidades clave:Peticiones Únicas: Los clientes pueden solicitar una llamada a la API que se procesa de forma asincrónica.Tareas Programadas: Los clientes pueden programar peticiones recurrentes a la API en intervalos definidos, lo cual es ideal para el monitoreo o la actualización de datos periódica.El servidor utiliza stream_select para manejar de forma eficiente las conexiones de sockets y cURL multi para las peticiones HTTP concurrentes, garantizando un alto rendimiento. También gestiona la persistencia de las tareas programadas en un archivo JSON, lo que permite que el estado del servidor se mantenga incluso después de un reinicio.
  
  
📂 Estructura del ProyectoLa organización del código sigue un estándar claro, separando la lógica de la aplicación de los archivos de configuración y otros recursos./tu-proyecto/
├── /config/
│   └── config.ini          # Archivo de configuración del servidor y la API
├── /log/
│   └── server_errors.log   # Archivo de registro de errores del servidor
├── /src/
│   └── WebSocketServer.php # La clase principal del servidor
├── /tasks/
│   └── scheduled_tasks.json# Almacenamiento de tareas programadas
└── server.php          # Punto de entrada para ejecutar el servidor
├── .gitignore              # Archivo para ignorar en Git (logs, certificados)
├── certificate.pem         # Certificado SSL
├── private_key.key         # Clave privada SSL
└── README.md               # Documentación del proyecto


⚙️ RequisitosAsegúrate de tener instalado lo siguiente:
    PHP 7.4+: Con las extensiones sockets y curl habilitadas.
    OpenSSL: Necesario para generar los certificados SSL/TLS y manejar las conexiones seguras (WSS).Generar Certificados SSL/TLS
    Para que el servidor funcione con el protocolo wss://, necesitas un par de archivos de certificado y clave. Para entornos de desarrollo, puedes usar OpenSSL para generar certificados autofirmados:# 1. Genera una clave privada de 2048 bits
openssl genrsa -out private_key.key 2048

# 2. Genera un certificado autofirmado (válido por un año)
openssl req -new -x509 -key private_key.key -out certificate.pem -days 365
Estos archivos (certificate.pem y private_key.key) deben colocarse en el directorio raíz de tu proyecto.

🚀 Instalación y Uso1. Clonar el Repositoriogit clone [https://github.com/tu-usuario/tu-repositorio.git](https://github.com/tu-usuario/tu-repositorio.git)
cd tu-repositorio
2. Configurar el ServidorEdita el archivo de configuración config/config.ini para que coincida con tu entorno:[server]
host = "0.0.0.0"
port = 8443
ssl_cert_path = "certificate.pem"
ssl_key_path = "private_key.key"
valid_token = "tu-token-de-autenticacion-seguro" ; ¡IMPORTANTE! Cambia esto

[api]
base_url = "http://localhost:3000"

[logging]
log_file = "server_errors.log"

[tasks]
tasks_file = "scheduled_tasks.json"
⚠️ ¡No olvides cambiar valid_token por un valor seguro y único!3. Ejecutar el ServidorUna vez que la configuración esté lista, inicia el servidor desde la terminal:php public/server.php
Verás un mensaje de confirmación que indica que el servidor está escuchando en el puerto configurado.🤝 Conexión y Comunicación del ClienteLos clientes deben conectarse al servidor utilizando el protocolo WSS.AutenticaciónEl servidor requiere que los clientes incluyan un token de autenticación en la cabecera Sec-WebSocket-Protocol durante el handshake inicial. Este valor debe coincidir con valid_token del archivo config.ini.Formato de MensajeLos mensajes enviados desde el cliente al servidor deben ser objetos JSON con la siguiente estructura:CampoTipoDescripciónObligatoriopathstringLa ruta de la API (ej. /users/123).✅methodstringEl método HTTP (GET, POST, PUT, DELETE).✅bodyobjectEl cuerpo de la petición. Opcional.❌intervalintegerEl intervalo en segundos para una tarea programada. 0 para una petición única. Opcional.❌Ejemplo de Petición Única (GET){
  "path": "/products/list",
  "method": "GET"
}
Ejemplo de Tarea Programada (POST){
  "path": "/data/sync",
  "method": "POST",
  "body": {
    "status": "pending"
  },
  "interval": 300  ; Se ejecutará cada 5 minutos
}
📈 Futuras Mejoras
Autenticación JWT: Reemplazar el token actual por un sistema de JSON Web Tokens más robusto y seguro.Gestión de Errores: Implementar un sistema de logging más detallado y con niveles de severidad.Cliente de Ejemplo: Crear un cliente simple en JavaScript para mostrar la conexión y la comunicación.Contenedor Docker: Crear un Dockerfile para facilitar el despliegue del servidor.📄 LicenciaEste proyecto se distribuye bajo la licencia MIT.
