<?php
declare(strict_types=1);

/**
 * Clase principal que gestiona un servidor WebSocket seguro (WSS)
 * con capacidad para realizar y gestionar peticiones asincrónicas a una API REST.
 *
 * @property-read resource $serverSocket El recurso del socket del servidor.
 * @property-read array $clients Array de sockets de clientes conectados.
 * @property-read array $requestLog Historial de peticiones a la API.
 * @property-read resource $multiHandler El manejador para peticiones cURL concurrentes.
 * @property-read array $pendingApiRequests Peticiones cURL pendientes, mapeadas por su ID de handle.
 * @property-read array $scheduledTasks Tareas programadas para su ejecución periódica.
 */
class WebSocketServer
{
    private $serverSocket;
    private array $clients = [];
    private array $authorizedClients = [];
    private array $requestLog = [];
    private $multiHandler;
    private array $pendingApiRequests = [];
    private array $scheduledTasks = [];

    // Propiedades para la configuración cargada desde el archivo .ini
    private string $host;
    private int $port;
    private string $logFile;
    private string $apiBaseUrl;
    private string $sslCertPath;
    private string $sslKeyPath;
    private string $validToken;
    private string $tasksFile;
    private string $configPath;
    private string $logPath;
    private string $tasksPath;

    /**
     * Constructor de la clase.
     * * Inicializa y configura el socket del servidor con SSL/TLS.
     * * Carga las tareas programadas desde el archivo de persistencia.
     * @throws Exception si el socket no puede ser creado o enlazado.
     */
    public function __construct(array $paths)
    {
        // Asignar las rutas pasadas por el constructor
        $this->configPath = $paths['config'];
        $this->logPath = $paths['log'];
        $this->tasksPath = $paths['tasks'];

        $this->loadConfig();
        
        try {
            if (!file_exists($this->sslCertPath) || !file_exists($this->sslKeyPath)) {
                throw new Exception("Archivos de certificado o clave SSL no encontrados.");
            }

            $context = stream_context_create([
                'ssl' => [
                    'local_cert' => $this->sslCertPath,
                    'local_pk'   => $this->sslKeyPath,
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true,
                ]
            ]);

            $this->serverSocket = stream_socket_server("tls://" . $this->host . ":" . $this->port, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
            
            if ($this->serverSocket === false) {
                throw new Exception("Error al crear el socket SSL: {$errstr} ({$errno})");
            }
            
            echo "Servidor WebSocket (WSS) escuchando en " . $this->host . ":" . $this->port . "\n";
        } catch (Exception $e) {
            die($e->getMessage());
        }
        
        $this->clients[] = $this->serverSocket;
        $this->multiHandler = curl_multi_init();
        $this->loadScheduledTasks();
    }
    
    /**
     * Carga la configuración desde el archivo .ini y la asigna a las propiedades de la clase.
     * @throws Exception Si el archivo de configuración no existe o no puede ser leído.
     */
     private function loadConfig(): void
    {
        $configFile = $this->configPath . 'config.ini';
        if (!file_exists($configFile) || !is_readable($configFile)) {
            throw new Exception("Archivo de configuración '{$configFile}' no encontrado o no se puede leer.");
        }
        
        $config = parse_ini_file($configFile, true, INI_SCANNER_TYPED);
        if ($config === false) {
            throw new Exception("Error al analizar el archivo de configuración '{$configFile}'.");
        }
        
        $this->host = $config['server']['host'] ?? '0.0.0.0';
        $this->port = (int)($config['server']['port'] ?? 8443);
        $this->sslCertPath = $config['server']['ssl_cert_path'] ?? 'certificate.pem';
        $this->sslKeyPath = $config['server']['ssl_key_path'] ?? 'private_key.key';
        $this->validToken = $config['server']['valid_token'] ?? 'your-secure-auth-token';
        
        $this->apiBaseUrl = $config['api']['base_url'] ?? 'http://localhost:3000';
        $this->logFile = $config['logging']['log_file'] ?? 'server_errors.log';
        $this->tasksFile = $config['tasks']['tasks_file'] ?? 'scheduled_tasks.json';
    }

    /**
     * Inicia el bucle principal del servidor.
     * * Este bucle maneja las conexiones, la comunicación con los clientes,
     * y las peticiones asincrónicas a la API REST de forma concurrente.
     */
    public function run(): void
    {
        while (true) {
            $readSockets = $this->clients;
            $writeSockets = null;
            $exceptSockets = null;

            stream_select($readSockets, $writeSockets, $exceptSockets, 0);
            
            foreach ($readSockets as $currentSocket) {
                if ($currentSocket === $this->serverSocket) {
                    $this->handleNewConnection();
                } else {
                    $this->handleClientRequest($currentSocket);
                }
            }
            
            $this->checkPendingApiRequests();
            $this->checkScheduledTasks();
        }
    }

    /**
     * Destructor de la clase.
     * * Cierra el socket del servidor y el manejador cURL multi al finalizar el script.
     * * Guarda las tareas programadas en el archivo de persistencia.
     */
    public function __destruct()
    {
        $this->saveScheduledTasks();
        stream_socket_shutdown($this->serverSocket, STREAM_SHUT_RDWR);
        curl_multi_close($this->multiHandler);
    }

    // --- Métodos de manejo del servidor ---

    /**
     * Acepta una nueva conexión de un cliente, realiza el handshake SSL y WebSocket.
     */
    private function handleNewConnection(): void
    {
        $newClient = @stream_socket_accept($this->serverSocket, -1);
        if ($newClient === false) {
            $this->logError("Error al aceptar la conexión SSL.");
            return;
        }
        
        stream_socket_enable_crypto($newClient, true, STREAM_CRYPTO_METHOD_TLS_SERVER);
        
        $header = fread($newClient, 2048);
        if ($header === false) {
            $this->logError("Error al leer el handshake desde un nuevo cliente.");
            fclose($newClient);
            return;
        }

        if (!$this->performHandshake($header, $newClient)) {
            $this->logError("Handshake fallido con un nuevo cliente.");
            fclose($newClient);
            return;
        }
        
        $this->clients[] = $newClient;
        echo "Nuevo cliente conectado.\n";
    }

    /**
     * Maneja un mensaje entrante de un cliente.
     * * Analiza el mensaje (esperando un JSON) y decide si ejecutar una
     * petición única o programar una tarea repetitiva.
     * @param resource $currentSocket El socket del cliente que envió el mensaje.
     */
    private function handleClientRequest($currentSocket): void
    {
        if (!isset($this->authorizedClients[(int)$currentSocket])) {
            $this->logError("Intento de petición no autorizada desde el socket " . (int)$currentSocket);
            $this->sendWebSocketResponse($currentSocket, ['status' => 'error', 'message' => 'No autorizado.']);
            $this->disconnectClient($currentSocket);
            return;
        }
        
        $data = @fread($currentSocket, 2048);
        if ($data === false || $data === '') {
            $this->disconnectClient($currentSocket);
            return;
        }

        $decodedMessage = $this->unmask($data);
        $requestData = json_decode($decodedMessage, true);
        
        if (json_last_error() !== JSON_ERROR_NONE || !isset($requestData['path'], $requestData['method'])) {
            $this->logError("Mensaje no válido o JSON incorrecto desde el socket " . (int)$currentSocket);
            $this->sendWebSocketResponse($currentSocket, ['status' => 'error', 'message' => 'Mensaje no válido, debe ser JSON con path y method.']);
            return;
        }
        
        $requestUrl = $this->apiBaseUrl . $requestData['path'];
        $requestMethod = strtoupper($requestData['method']);
        $requestPayload = $requestData['body'] ?? null;
        $interval = (int)($requestData['interval'] ?? 0);
        
        if ($interval > 0) {
            $this->scheduledTasks[(int)$currentSocket] = [
                'url' => $requestUrl,
                'method' => $requestMethod,
                'payload' => $requestPayload,
                'interval' => $interval,
                'next_run' => microtime(true)
            ];
            $this->saveScheduledTasks(); // Guarda las tareas al agregar una nueva
            echo "Tarea programada para el cliente " . (int)$currentSocket . " cada " . $interval . " segundos.\n";
            $this->sendWebSocketResponse($currentSocket, ['status' => 'success', 'message' => 'Tarea programada.']);
        } else {
            $this->executeApiCall($currentSocket, $requestUrl, $requestMethod, $requestPayload);
            echo "Petición única en cola para el cliente " . (int)$currentSocket . "\n";
        }
    }

    /**
     * Desconecta a un cliente y limpia sus tareas y recursos asociados.
     * @param resource $socket El socket del cliente a desconectar.
     */
    private function disconnectClient($socket): void
    {
        $index = array_search($socket, $this->clients, true);
        if ($index !== false) {
            unset($this->clients[$index]);
            unset($this->authorizedClients[(int)$socket]);
            unset($this->scheduledTasks[(int)$socket]);
            $this->saveScheduledTasks(); // Guarda el estado después de una desconexión
            fclose($socket);
            echo "Cliente desconectado.\n";
        }
    }

    /**
     * Registra un mensaje de error en el archivo de log.
     * @param string $message El mensaje de error a registrar.
     */
    private function logError(string $message): void
    {
        $error = date('Y-m-d H:i:s') . " - " . $message . "\n";
        file_put_contents($this->logPath . $this->logFile, $error, FILE_APPEND | LOCK_EX);
        echo "ERROR: " . $message . "\n";
    }

    // --- Métodos de persistencia ---

    /**
     * Carga las tareas programadas desde el archivo de persistencia.
     */
    private function loadScheduledTasks(): void
    {
        if (file_exists($this->tasksPath . $this->tasksFile)) {
            $jsonContent = file_get_contents($this->tasksPath . $this->tasksFile);
            $tasks = json_decode($jsonContent, true);
            if (is_array($tasks)) {
                $this->scheduledTasks = $tasks;
                echo "Tareas programadas cargadas desde el archivo de estado.\n";
            }
        }
    }

    /**
     * Guarda las tareas programadas en el archivo de persistencia en formato JSON.
     */
   private function saveScheduledTasks(): void
    {
        $jsonContent = json_encode($this->scheduledTasks, JSON_PRETTY_PRINT);
        file_put_contents($this->tasksPath . $this->tasksFile, $jsonContent, LOCK_EX);
    }

    // --- Métodos de la API y WebSocket ---

    /**
     * Comprueba las peticiones cURL pendientes y procesa las que han finalizado.
     */
    private function checkPendingApiRequests(): void
    {
        do {
            $status = curl_multi_exec($this->multiHandler, $active);
        } while ($status === CURLM_CALL_MULTI_PERFORM);

        while ($done = curl_multi_info_read($this->multiHandler)) {
            $handle = $done['handle'];
            $handleId = (int)$handle;

            if (!isset($this->pendingApiRequests[$handleId])) {
                continue;
            }

            $requestInfo = $this->pendingApiRequests[$handleId];
            $clientSocket = $requestInfo['socket'];
            
            $apiResponse = $this->processApiCallResponse($handle);
            
            $this->requestLog[] = [
                'socket_id' => (int)$clientSocket,
                'request_timestamp' => date('Y-m-d H:i:s', (int)$requestInfo['start_time']),
                'api_url' => $requestInfo['url'],
                'api_method' => $requestInfo['method'],
                'response_status' => $apiResponse['status'],
                'response_time_ms' => round((microtime(true) - $requestInfo['start_time']) * 1000)
            ];

            echo "Petición API (" . $requestInfo['method'] . ") a " . $requestInfo['url'] . " procesada. Estado: " . $apiResponse['status'] . "\n";
            $this->sendWebSocketResponse($clientSocket, $apiResponse['data']);

            curl_multi_remove_handle($this->multiHandler, $handle);
            unset($this->pendingApiRequests[$handleId]);
            curl_close($handle);
        }
    }
    
    /**
     * Comprueba las tareas programadas y ejecuta las que han alcanzado su tiempo.
     */
    private function checkScheduledTasks(): void
    {
        $currentTime = microtime(true);
        foreach ($this->scheduledTasks as $socketId => $task) {
            if ($currentTime >= $task['next_run']) {
                $socket = array_filter($this->clients, fn($s) => (int)$s === $socketId);
                $socket = reset($socket);
                
                if ($socket && isset($this->authorizedClients[(int)$socket])) {
                    $this->executeApiCall($socket, $task['url'], $task['method'], $task['payload']);
                    $this->scheduledTasks[$socketId]['next_run'] = $currentTime + $task['interval'];
                    $this->saveScheduledTasks();
                } else {
                    unset($this->scheduledTasks[$socketId]);
                    $this->saveScheduledTasks();
                }
            }
        }
    }
    
    /**
     * Programa una llamada a la API agregándola al pool de peticiones.
     * @param resource $currentSocket El socket del cliente asociado.
     * @param string $url La URL de la API.
     * @param string $method El método HTTP (GET, POST, etc.).
     * @param ?string $payload El cuerpo de la petición.
     */
    private function executeApiCall($currentSocket, string $url, string $method, ?string $payload): void
    {
        $curlHandle = $this->createApiCall($url, $method, $payload);
        $this->pendingApiRequests[(int)$curlHandle] = [
            'socket' => $currentSocket,
            'start_time' => microtime(true),
            'url' => $url,
            'method' => $method,
            'payload' => $payload
        ];
    }

    /**
     * Inicializa un handle de cURL y lo añade al manejador multi.
     * @param string $url La URL de la API.
     * @param string $method El método HTTP.
     * @param ?string $payload El cuerpo de la petición.
     * @return resource El handle cURL creado.
     */
    private function createApiCall(string $url, string $method, ?string $payload)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);

        if ($payload) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($curl, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'Content-Length: ' . strlen($payload)]);
        }

        curl_multi_add_handle($this->multiHandler, $curl);
        return $curl;
    }
    
    /**
     * Procesa la respuesta de una petición cURL finalizada.
     * @param resource $curlHandle El handle de la petición cURL.
     * @return array Un array con el estado y los datos de la respuesta.
     */
    private function processApiCallResponse($curlHandle): array
    {
        $response = curl_multi_getcontent($curlHandle);
        $httpCode = curl_getinfo($curlHandle, CURLINFO_HTTP_CODE);
        $curlError = curl_error($curlHandle);

        if ($curlError) {
            return ['status' => 'error', 'data' => ['message' => 'Error de cURL: ' . $curlError]];
        }
        
        $decodedResponse = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['status' => 'error', 'data' => ['message' => 'Respuesta de la API no es un JSON válido.']];
        }

        return [
            'status' => ($httpCode >= 200 && $httpCode < 300) ? 'success' : 'error',
            'data' => $decodedResponse ?? $response
        ];
    }
    
    /**
     * Envía una respuesta al cliente a través del socket WebSocket.
     * @param resource $socket El socket del cliente.
     * @param mixed $data Los datos a enviar (se codificarán a JSON).
     */
    private function sendWebSocketResponse($socket, $data): void
    {
        $response = json_encode($data);
        $maskedResponse = $this->mask($response);
        fwrite($socket, $maskedResponse, strlen($maskedResponse));
    }
    
    /**
     * Realiza el handshake de WebSocket con un nuevo cliente y valida el token.
     * @param string $receivedHeader La cabecera de la petición inicial del cliente.
     * @param resource $clientConn El socket del cliente.
     * @return bool Verdadero si el handshake y la autenticación fueron exitosos, falso en caso contrario.
     */
    private function performHandshake(string $receivedHeader, $clientConn): bool
    {
        $headers = [];
        $lines = preg_split("/\r\n/", $receivedHeader);
        foreach ($lines as $line) {
            $line = trim($line);
            if (preg_match('/\A(\S+): (.*)\z/', $line, $matches)) {
                $headers[$matches[1]] = $matches[2];
            }
        }
        
        if (!isset($headers['Sec-WebSocket-Key'])) {
            return false;
        }

        $clientToken = $headers['Sec-WebSocket-Protocol'] ?? null;
        if (!$this->validateToken($clientToken)) {
            $this->logError("Intento de conexión con token inválido.");
            return false;
        }
        
        $this->authorizedClients[(int)$clientConn] = true;

        $secKey = $headers['Sec-WebSocket-Key'];
        $secAccept = base64_encode(pack('H*', sha1($secKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
        $upgrade = "HTTP/1.1 101 Switching Protocols\r\n" .
                   "Upgrade: websocket\r\n" .
                   "Connection: Upgrade\r\n" .
                   "Sec-WebSocket-Accept: {$secAccept}\r\n" .
                   "Sec-WebSocket-Protocol: {$clientToken}\r\n\r\n";

        return fwrite($clientConn, $upgrade, strlen($upgrade)) !== false;
    }

    /**
     * Valida el token de autenticación.
     * @param ?string $token El token enviado por el cliente.
     * @return bool Verdadero si el token es válido, falso en caso contrario.
     */
    private function validateToken(?string $token): bool
    {
        return $token === $this->validToken;
    }

    private function unmask(string $payload): string
    {
        $length = ord($payload[1]) & 127;
        if ($length === 126) {
            $masks = substr($payload, 4, 4);
            $data = substr($payload, 8);
        } elseif ($length === 127) {
            $masks = substr($payload, 10, 4);
            $data = substr($payload, 14);
        } else {
            $masks = substr($payload, 2, 4);
            $data = substr($payload, 6);
        }

        $text = '';
        for ($i = 0; $i < strlen($data); ++$i) {
            $text .= $data[$i] ^ $masks[$i % 4];
        }
        return $text;
    }

    private function mask(string $text): string
    {
        $b1 = 0x80 | (0x1 & 0x0f);
        $length = strlen($text);

        if ($length <= 125) {
            $header = pack('C', $b1) . pack('C', $length);
        } elseif ($length < 65536) {
            $header = pack('C', $b1) . pack('C', 126) . pack('n', $length);
        } else {
            $header = pack('C', $b1) . pack('C', 127) . pack('J', $length);
        }

        return $header . $text;
    }
}


?>