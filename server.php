<?php

/**
 * Desactiva el tiempo de espera máximo de ejecución del script.
 * Es necesario para que el servidor se ejecute de forma indefinida.
 */
set_time_limit(0);

// Configuracion de errores
ini_set('display_errors', 1);
error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE);

// Define el separador de directorio
define('DS', DIRECTORY_SEPARATOR);

// Define la ruta base del proyecto
// __DIR__ se refiere al directorio actual ('public'). '..' sube un nivel.
define('ROOT_PATH', realpath(dirname(__FILE__)).DS);

// Define la ruta de configuraciones
define('CONF_PATH', ROOT_PATH . 'config' . DS);

// Define la ruta de fuentes (clases)
define('SRC_PATH', ROOT_PATH . 'src' . DS);

// Define la ruta de log
define('LOG_PATH', ROOT_PATH . 'log' . DS); 

// Define la ruta de tareas
define('TASK_PATH', ROOT_PATH . 'tasks' . DS); 

// Incluir la clase WebSocketServer
require_once SRC_PATH . 'WebSocketServer.php';

// Crear un array de rutas para inyectar en la clase
$paths = [
    'config' => CONF_PATH,
    'log' => LOG_PATH,
    'tasks' => TASK_PATH,
];

try {
    // Inicializar y ejecutar el servidor, pasando las rutas
    $server = new WebSocketServer($paths);
    $server->run();
} catch (Exception $e) {
    die("Error al iniciar el servidor: " . $e->getMessage());
}

exit();