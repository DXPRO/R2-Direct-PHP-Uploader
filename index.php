<?php
/**
 * Uploader Seguro para Cloudflare R2 via Presigned URLs
 * Compatível com PHP 8.2+ e servidores LiteSpeed / Hostinger
 * 
 * Permite upload direto do navegador para o Cloudflare R2,
 * mitigando timeouts e consumo de banda na hospedagem compartilhada.
 */

// Iniciar sessão com flags estritos de segurança
session_start([
    'cookie_lifetime' => 0,
    'cookie_path' => '/',
    'cookie_secure' => isset($_SERVER['HTTPS']),
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'use_only_cookies' => true
]);

// Evitar indexação de mecanismos de busca por header HTTP
header("X-Robots-Tag: noindex, nofollow, noarchive", true);

// Carregar configurações confidenciais
$configPath = __DIR__ . '/env.php';
if (!file_exists($configPath)) {
    http_response_code(500);
    exit('Erro de Configuração: O arquivo env.php nao foi encontrado.');
}
$config = require $configPath;

// Habilitar logs e ocultar exibição de erros dependendo do ambiente
if (($config['APP_ENV'] ?? 'production') === 'development') {
    ini_set('display_errors', '1');
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', '0');
    error_reporting(0);
}

// Gerar Token CSRF se não existir
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Autoload do Composer
$autoloadPath = __DIR__ . '/vendor/autoload.php';
$hasComposer = file_exists($autoloadPath);
if ($hasComposer) {
    require_once $autoloadPath;
}

// Helper para gerar UUID v4 criptograficamente seguro
function generate_uuidv4(): string {
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // Versão 4
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // Variante RFC 4122
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

// Helper para sanitizar nomes de arquivos de forma amigável e segura
function sanitize_filename(string $filename): string {
    $pathInfo = pathinfo($filename);
    $name = $pathInfo['filename'] ?? '';
    $ext = isset($pathInfo['extension']) ? strtolower($pathInfo['extension']) : '';

    // Dicionário de conversão de acentos e caracteres especiais para compatibilidade global
    $accentMap = [
        'á'=>'a', 'à'=>'a', 'â'=>'a', 'ã'=>'a', 'ä'=>'a', 'å'=>'a', 'æ'=>'ae',
        'é'=>'e', 'è'=>'e', 'ê'=>'e', 'ë'=>'e', 'í'=>'i', 'ì'=>'i', 'î'=>'i', 'ï'=>'i',
        'ó'=>'o', 'ò'=>'o', 'ô'=>'o', 'õ'=>'o', 'ö'=>'o', 'ø'=>'o', 'œ'=>'oe',
        'ú'=>'u', 'ù'=>'u', 'û'=>'u', 'ü'=>'u', 'ç'=>'c', 'ñ'=>'n',
        'Á'=>'A', 'À'=>'A', 'Â'=>'A', 'Ã'=>'A', 'Ä'=>'A', 'Å'=>'A', 'Æ'=>'AE',
        'É'=>'E', 'È'=>'E', 'Ê'=>'E', 'Ë'=>'E', 'Í'=>'I', 'Ì'=>'I', 'Î'=>'I', 'Ï'=>'I',
        'Ó'=>'O', 'Ò'=>'O', 'Ô'=>'O', 'Õ'=>'O', 'Ö'=>'O', 'Ø'=>'O', 'Œ'=>'OE',
        'Ú'=>'U', 'Ù'=>'U', 'Û'=>'U', 'Ü'=>'U', 'Ç'=>'C', 'Ñ'=>'N'
    ];
    $name = strtr($name, $accentMap);
    $name = strtolower($name);

    // Substituir qualquer caractere não alfanumérico por hífen
    $name = preg_replace('/[^a-z0-9_\-]/', '-', $name);
    // Substituir múltiplos delimitadores por um único
    $name = preg_replace('/[\-_]+/', '-', $name);
    // Limpar delimitadores das bordas
    $name = trim($name, '-_');

    if (empty($name)) {
        $name = 'arquivo';
    }

    return $ext ? $name . '.' . $ext : $name;
}

// Helper para comparação de strings em tempo constante (segurança anti-timing attacks)
function safe_compare(string $known, string $user): bool {
    return hash_equals($known, $user);
}

// Helper para gravar logs de depuração locais
function write_log(string $message): void {
    global $config;
    if (empty($config['ENABLE_DEBUG_LOG'])) {
        return;
    }
    $logFile = __DIR__ . '/uploader.log';
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[{$timestamp}] {$message}" . PHP_EOL;
    @file_put_contents($logFile, $logMessage, FILE_APPEND);
}

// Helper para inicializar o cliente do Cloudflare R2
function get_r2_client(array $config): Aws\S3\S3Client {
    return new Aws\S3\S3Client([
        'credentials' => [
            'key'    => $config['R2_ACCESS_KEY'],
            'secret' => $config['R2_SECRET_KEY'],
        ],
        'region' => 'auto',
        'endpoint' => "https://" . $config['R2_ACCOUNT_ID'] . ".r2.cloudflarestorage.com",
        'version' => 'latest',
        'use_path_style_endpoint' => true,
        'http' => [
            'verify' => false, // Evita falhas de SSL em servidores com certificados CA desatualizados
        ],
    ]);
}

// Roteamento de Ações do Backend
$error = '';
$successLink = '';

// 1. Processo de Login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    // Validação de Honeypot (campo oculto invisível a humanos)
    if (!empty($_POST['username'])) {
        usleep(rand(500000, 1500000));
        header("Location: index.php");
        exit;
    }

    // Validação do Token CSRF
    if (empty($_POST['csrf_token']) || !safe_compare($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = 'Token de seguranca invalido. Tente novamente.';
    } else {
        $password = $_POST['password'] ?? '';
        $storedHash = $config['UPLOAD_PASSWORD_HASH'] ?? '';

        if (password_verify($password, $storedHash)) {
            session_regenerate_id(true);
            $_SESSION['authenticated'] = true;
            header("Location: index.php");
            exit;
        } else {
            usleep(rand(500000, 1000000));
            $error = 'Senha incorreta.';
        }
    }
}

// 2. Processo de Logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header("Location: index.php");
    exit;
}

// Verificação de autenticação
$isAuthenticated = !empty($_SESSION['authenticated']);

// 3. Processo de Geração de Presigned URL (Somente Autenticados)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action'] === 'get_presigned_url') {
    header('Content-Type: application/json');

    if (!$isAuthenticated) {
        write_log("Erro de Autenticacao: Tentativa de geracao de URL pre-assinada sem login.");
        http_response_code(403);
        echo json_encode(['error' => 'Acesso nao autorizado. Faca o login novamente.']);
        exit;
    }

    // Capturar o JSON enviado pelo navegador
    $jsonInput = file_get_contents('php://input');
    $requestData = json_decode($jsonInput, true);

    if (!$requestData) {
        write_log("Erro na requisicao: JSON invalido.");
        http_response_code(400);
        echo json_encode(['error' => 'Dados de requisicao invalidos.']);
        exit;
    }

    // Validação do Token CSRF
    $csrfToken = $requestData['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($csrfToken) || !safe_compare($_SESSION['csrf_token'], $csrfToken)) {
        write_log("Erro de CSRF: Token CSRF invalido na geracao de URL assinada.");
        http_response_code(400);
        echo json_encode(['error' => 'Token CSRF invalido ou expirado.']);
        exit;
    }

    // Validação do Honeypot de Upload
    if (!empty($requestData['upload_honeypot'])) {
        write_log("Honeypot de upload preenchido (Bot detectado na requisicao de URL assinada).");
        http_response_code(200);
        echo json_encode(['success' => true, 'url' => 'https://example.com/honeypot_active']);
        exit;
    }

    if (!$hasComposer) {
        write_log("Erro no servidor: Dependencias do Composer (AWS SDK) ausentes.");
        http_response_code(500);
        echo json_encode(['error' => 'Dependencias do R2 ausentes no servidor. Execute "composer install".']);
        exit;
    }

    $fileNameOriginal = $requestData['fileName'] ?? '';
    $fileSize = (int) ($requestData['fileSize'] ?? 0);
    $mimeType = $requestData['mimeType'] ?? 'application/octet-stream';

    if (empty($fileNameOriginal)) {
        write_log("Erro: Nome de arquivo nao informado.");
        http_response_code(400);
        echo json_encode(['error' => 'Nome do arquivo nao fornecido.']);
        exit;
    }

    // Validar Tamanho Máximo (500MB para upload direto)
    $maxFileSize = 500 * 1024 * 1024; // 500MB
    if ($fileSize > $maxFileSize) {
        write_log("Arquivo excede limite de 500MB. Tamanho relatado: {$fileSize} bytes");
        http_response_code(400);
        echo json_encode(['error' => 'O arquivo excede o limite maximo de seguranca de 500MB.']);
        exit;
    }

    // Sanitizar nome e extensão
    $pathInfo = pathinfo($fileNameOriginal);
    $extension = isset($pathInfo['extension']) ? strtolower($pathInfo['extension']) : '';

    // Whitelist estrita de extensões permitidas
    $allowedExtensions = ['exe', 'zip', 'rar', '7z', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'csv', 'mp4'];
    if (!in_array($extension, $allowedExtensions, true)) {
        write_log("Extensao nao permitida: '{$extension}'");
        http_response_code(400);
        echo json_encode(['error' => 'Extensao de arquivo nao permitida por motivos de seguranca.']);
        exit;
    }

    // Proteção extra contra MIME-Types perigosos de script
    $blockedMimes = ['text/html', 'application/x-httpd-php', 'text/javascript', 'application/javascript'];
    if (in_array($mimeType, $blockedMimes, true)) {
        write_log("MIME bloqueado na assinatura: '{$mimeType}'");
        http_response_code(400);
        echo json_encode(['error' => 'Tipo de conteudo invalido ou malicioso detectado.']);
        exit;
    }

    // Gerar nome de arquivo higienizado baseado no nome original (sobrescreve arquivos iguais no R2)
    $newFileName = sanitize_filename($fileNameOriginal);
    $friendlyName = $newFileName;

    try {
        write_log("Preparando URL pre-assinada para arquivo original: '{$fileNameOriginal}' | Nome no R2: '{$newFileName}'");

        // Inicializar Cliente do Cloudflare R2
        $s3Client = get_r2_client($config);

        $bucket = $config['R2_BUCKET_NAME'];
        
        // Se for um executável, usar cabeçalho para download forçado (attachment)
        $contentDisposition = ($extension === 'exe') 
            ? 'attachment; filename="' . $friendlyName . '"'
            : 'inline; filename="' . $friendlyName . '"';

        // Montar o comando PutObject
        $cmd = $s3Client->getCommand('PutObject', [
            'Bucket' => $bucket,
            'Key'    => $newFileName,
            'ContentType' => $mimeType,
            'ContentDisposition' => $contentDisposition,
        ]);

        // Gerar a URL pré-assinada válida por 20 minutos
        $request = $s3Client->createPresignedRequest($cmd, '+20 minutes');
        $presignedUrl = (string) $request->getUri();

        // Gerar a URL pública final onde o arquivo estará acessível após o upload
        $publicBaseUrl = rtrim($config['R2_PUBLIC_URL'], '/');
        $publicUrl = $publicBaseUrl . '/' . $newFileName;

        write_log("URL pre-assinada gerada com sucesso. Validade: 20 min.");

        echo json_encode([
            'success' => true,
            'presignedUrl' => $presignedUrl,
            'publicUrl' => $publicUrl,
            'friendlyName' => $friendlyName,
            'contentDisposition' => $contentDisposition
        ]);
        exit;

    } catch (Throwable $e) {
        write_log("FALHA NA GERACAO DA URL ASSINADA: " . $e->getMessage() . "\nTrace:\n" . $e->getTraceAsString());
        http_response_code(500);
        $errorMsg = (($config['APP_ENV'] ?? 'production') === 'development') 
            ? 'Erro R2: ' . $e->getMessage() 
            : 'Erro interno ao preparar a conexao com o Cloudflare R2.';
        echo json_encode(['error' => $errorMsg]);
        exit;
    }
}

// 4. API de Listagem de Arquivos (Somente Autenticados)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'list_files') {
    header('Content-Type: application/json');

    if (!$isAuthenticated) {
        write_log("Erro de Autenticacao: Tentativa de listagem de arquivos sem login.");
        http_response_code(403);
        echo json_encode(['error' => 'Acesso nao autorizado. Faca o login novamente.']);
        exit;
    }

    if (!$hasComposer) {
        write_log("Erro no servidor: Dependencias do Composer (AWS SDK) ausentes na listagem.");
        http_response_code(500);
        echo json_encode(['error' => 'Dependencias do R2 ausentes no servidor.']);
        exit;
    }

    try {
        $s3Client = get_r2_client($config);
        $bucket = $config['R2_BUCKET_NAME'];

        // Listar objetos do bucket
        $result = $s3Client->listObjectsV2([
            'Bucket' => $bucket
        ]);

        $files = [];
        if (isset($result['Contents'])) {
            $publicBaseUrl = rtrim($config['R2_PUBLIC_URL'], '/');
            foreach ($result['Contents'] as $object) {
                // Ignorar diretórios fictícios (chaves que terminam com /)
                if (substr($object['Key'], -1) === '/') {
                    continue;
                }
                
                $key = $object['Key'];
                $size = $object['Size'];
                
                // Formatar tamanho amigável
                $formattedSize = '0 B';
                if ($size > 0) {
                    $units = ['B', 'KB', 'MB', 'GB'];
                    $i = floor(log($size, 1024));
                    $formattedSize = round($size / pow(1024, $i), 2) . ' ' . $units[$i];
                }

                $files[] = [
                    'key' => $key,
                    'size' => $formattedSize,
                    'last_modified' => $object['LastModified']->getTimestamp(),
                    'url' => $publicBaseUrl . '/' . rawurlencode($key)
                ];
            }

            // Ordenar por data de modificação decrescente (mais recentes primeiro)
            usort($files, function($a, $b) {
                return $b['last_modified'] <=> $a['last_modified'];
            });
        }

        echo json_encode(['success' => true, 'files' => $files]);
        exit;

    } catch (Throwable $e) {
        write_log("FALHA NA LISTAGEM DE ARQUIVOS: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Erro interno ao listar arquivos do Cloudflare R2.']);
        exit;
    }
}

// 5. API de Exclusao de Arquivo (Somente Autenticados)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action'] === 'delete_file') {
    header('Content-Type: application/json');

    if (!$isAuthenticated) {
        write_log("Erro de Autenticacao: Tentativa de exclusao de arquivo sem login.");
        http_response_code(403);
        echo json_encode(['error' => 'Acesso nao autorizado. Faca o login novamente.']);
        exit;
    }

    // Capturar o JSON enviado pelo navegador
    $jsonInput = file_get_contents('php://input');
    $requestData = json_decode($jsonInput, true);

    if (!$requestData) {
        write_log("Erro na requisicao de exclusao: JSON invalido.");
        http_response_code(400);
        echo json_encode(['error' => 'Dados de requisicao invalidos.']);
        exit;
    }

    // Validação do Token CSRF
    $csrfToken = $requestData['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($csrfToken) || !safe_compare($_SESSION['csrf_token'], $csrfToken)) {
        write_log("Erro de CSRF: Token CSRF invalido na exclusao de arquivo.");
        http_response_code(400);
        echo json_encode(['error' => 'Token CSRF invalido ou expirado.']);
        exit;
    }

    $fileKey = $requestData['key'] ?? '';
    if (empty($fileKey)) {
        write_log("Erro na exclusao: Chave do arquivo nao informada.");
        http_response_code(400);
        echo json_encode(['error' => 'Chave do arquivo nao fornecida.']);
        exit;
    }

    if (!$hasComposer) {
        write_log("Erro no servidor: Dependencias do Composer (AWS SDK) ausentes na exclusao.");
        http_response_code(500);
        echo json_encode(['error' => 'Dependencias do R2 ausentes no servidor.']);
        exit;
    }

    try {
        write_log("Tentando excluir arquivo do R2: '{$fileKey}'");

        $s3Client = get_r2_client($config);
        $bucket = $config['R2_BUCKET_NAME'];

        // Excluir o objeto do R2
        $s3Client->deleteObject([
            'Bucket' => $bucket,
            'Key'    => $fileKey
        ]);

        write_log("Arquivo '{$fileKey}' excluido com sucesso do R2.");
        echo json_encode(['success' => true]);
        exit;

    } catch (Throwable $e) {
        write_log("FALHA NA EXCLUSAO DO ARQUIVO: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Erro interno ao excluir o arquivo do Cloudflare R2.']);
        exit;
    }
}

// Renderização do HTML (Frontend)
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel de Armazenamento Anonimo</title>
    <!-- Impedir indexação por bots de busca -->
    <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
    <!-- Fonte Inter Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --bg-color: #080c14;
            --card-bg: rgba(17, 24, 39, 0.75);
            --border-color: rgba(75, 85, 99, 0.3);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-start: #6366f1; /* Indigo */
            --accent-end: #a855f7;   /* Purple */
            --accent-hover: #4f46e5;
            --success-color: #10b981;
            --error-color: #ef4444;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
            position: relative;
            overflow-x: hidden;
        }

        /* Efeito de luz decorativo de fundo (moderno) */
        body::before {
            content: '';
            position: absolute;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, rgba(0,0,0,0) 70%);
            top: -100px;
            left: -100px;
            z-index: -1;
        }
        body::after {
            content: '';
            position: absolute;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, rgba(168, 85, 247, 0.12) 0%, rgba(0,0,0,0) 70%);
            bottom: -150px;
            right: -150px;
            z-index: -1;
        }

        .container {
            width: 100%;
            max-width: 480px;
            z-index: 10;
        }

        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 18px;
            padding: 2.5rem 2rem;
            box-shadow: 0 20px 40px -15px rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .card-header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .card-title {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--text-primary) 30%, var(--text-secondary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        .card-subtitle {
            font-size: 0.875rem;
            color: var(--text-secondary);
            font-weight: 400;
        }

        /* Alertas de erro/sucesso */
        .alert {
            padding: 0.875rem 1rem;
            border-radius: 10px;
            font-size: 0.875rem;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            animation: fadeIn 0.3s ease;
        }
        .alert-error {
            background-color: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: var(--error-color);
        }
        .alert-success {
            background-color: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.25);
            color: var(--success-color);
        }

        /* Formulários */
        .form-group {
            margin-bottom: 1.25rem;
            position: relative;
        }

        .form-label {
            display: block;
            font-size: 0.8125rem;
            color: var(--text-secondary);
            font-weight: 500;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .form-input {
            width: 100%;
            padding: 0.875rem 1rem;
            background-color: rgba(31, 41, 55, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            color: var(--text-primary);
            font-size: 0.95rem;
            transition: all 0.2s ease;
            outline: none;
        }

        .form-input:focus {
            border-color: var(--accent-start);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);
            background-color: rgba(31, 41, 55, 0.8);
        }

        /* Botões */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 0.875rem 1rem;
            background: linear-gradient(135deg, var(--accent-start) 0%, var(--accent-end) 100%);
            border: none;
            border-radius: 10px;
            color: #ffffff;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
        }

        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
            opacity: 0.95;
        }

        .btn:active {
            transform: translateY(1px);
        }

        .btn-logout {
            background: transparent;
            border: 1px solid var(--border-color);
            box-shadow: none;
            color: var(--text-secondary);
            margin-top: 1.5rem;
            font-size: 0.8125rem;
            padding: 0.625rem;
        }

        .btn-logout:hover {
            background-color: rgba(239, 68, 68, 0.1);
            border-color: rgba(239, 68, 68, 0.3);
            color: var(--error-color);
            box-shadow: none;
        }

        /* Dropzone Component */
        .dropzone {
            border: 2px dashed rgba(99, 102, 241, 0.4);
            background-color: rgba(31, 41, 55, 0.25);
            border-radius: 14px;
            padding: 3rem 1.5rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.25s ease;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
        }

        .dropzone.dragover {
            border-color: var(--accent-end);
            background-color: rgba(168, 85, 247, 0.08);
            transform: scale(1.02);
        }

        .dropzone-icon {
            width: 48px;
            height: 48px;
            color: var(--accent-start);
            transition: transform 0.3s ease;
        }

        .dropzone:hover .dropzone-icon {
            transform: translateY(-4px);
        }

        .dropzone-text {
            font-size: 0.9rem;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        .dropzone-text strong {
            color: var(--text-primary);
        }

        .file-input {
            display: none;
        }

        /* Barra de Progresso do Upload */
        .progress-container {
            display: none;
            margin-top: 1.5rem;
            text-align: left;
        }

        .progress-header {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }

        .progress-bar-wrapper {
            width: 100%;
            height: 6px;
            background-color: rgba(31, 41, 55, 0.8);
            border-radius: 999px;
            overflow: hidden;
        }

        .progress-bar {
            width: 0%;
            height: 100%;
            background: linear-gradient(90deg, var(--accent-start) 0%, var(--accent-end) 100%);
            border-radius: 999px;
            transition: width 0.1s linear;
        }

        /* Resultado do Upload */
        .result-container {
            display: none;
            margin-top: 1.5rem;
            animation: fadeIn 0.4s ease;
        }

        .result-title {
            font-size: 0.875rem;
            color: var(--success-color);
            font-weight: 600;
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .copy-group {
            display: flex;
            gap: 0.5rem;
        }

        .copy-input {
            flex-grow: 1;
            font-family: monospace;
            font-size: 0.8rem;
            background-color: rgba(17, 24, 39, 0.9);
            border-color: rgba(16, 185, 129, 0.3);
            text-overflow: ellipsis;
        }

        .btn-copy {
            width: auto;
            min-width: 90px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            box-shadow: none;
            padding: 0.5rem 1rem;
            font-size: 0.8rem;
        }

        .btn-copy:hover {
            background-color: var(--border-color);
            box-shadow: none;
        }

        .btn-copy.success {
            background-color: rgba(16, 185, 129, 0.1);
            border-color: var(--success-color);
            color: var(--success-color);
        }

        /* Notificação de dependência */
        .composer-warning {
            background-color: rgba(239, 68, 68, 0.05);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: var(--text-secondary);
            font-size: 0.75rem;
            padding: 0.75rem;
            border-radius: 8px;
            margin-top: 1rem;
            text-align: center;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Estilos adicionais para galeria e toasts */
        .container.container-wide {
            max-width: 1000px;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 2rem;
            width: 100%;
        }

        @media (min-width: 820px) {
            .dashboard-grid {
                grid-template-columns: 380px 1fr;
                align-items: start;
            }
        }

        .uploader-section {
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
        }

        .gallery-section {
            display: flex;
            flex-direction: column;
            border-left: none;
            padding-left: 0;
            width: 100%;
        }

        @media (min-width: 820px) {
            .gallery-section {
                border-left: 1px solid var(--border-color);
                padding-left: 2rem;
            }
        }

        /* Botão de atualização */
        .btn-refresh {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            width: 34px;
            height: 34px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-refresh:hover {
            color: var(--text-primary);
            border-color: var(--text-secondary);
            background-color: rgba(255, 255, 255, 0.05);
        }

        .btn-refresh svg {
            transition: transform 0.5s ease;
        }

        .btn-refresh.spinning svg {
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            100% { transform: rotate(360deg); }
        }

        /* Caixa de busca */
        .search-box {
            position: relative;
            margin-bottom: 1.25rem;
            width: 100%;
        }

        .search-icon {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-secondary);
            pointer-events: none;
        }

        .search-input {
            padding-left: 2.5rem !important;
            height: 42px;
            font-size: 0.875rem !important;
        }

        /* Lista da Galeria */
        .gallery-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            max-height: 450px;
            overflow-y: auto;
            padding-right: 0.25rem;
        }

        .gallery-list::-webkit-scrollbar {
            width: 6px;
        }

        .gallery-list::-webkit-scrollbar-track {
            background: rgba(31, 41, 55, 0.2);
            border-radius: 99px;
        }

        .gallery-list::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 99px;
        }

        .gallery-list::-webkit-scrollbar-thumb:hover {
            background: var(--text-secondary);
        }

        .gallery-empty {
            text-align: center;
            color: var(--text-secondary);
            padding: 3rem 1rem;
            font-size: 0.875rem;
            border: 1px dashed var(--border-color);
            border-radius: 12px;
            background-color: rgba(31, 41, 55, 0.1);
        }

        /* Item de arquivo */
        .file-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem 1rem;
            background-color: rgba(31, 41, 55, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            transition: all 0.2s ease;
        }

        .file-item:hover {
            border-color: rgba(99, 102, 241, 0.4);
            background-color: rgba(31, 41, 55, 0.5);
            transform: translateY(-1px);
        }

        .file-info {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-grow: 1;
            min-width: 0;
        }

        .file-icon {
            width: 36px;
            height: 36px;
            background-color: rgba(99, 102, 241, 0.1);
            color: var(--accent-start);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            overflow: hidden;
        }

        .file-icon-img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        .file-meta {
            display: flex;
            flex-direction: column;
            min-width: 0;
        }

        .file-name {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            text-decoration: none;
        }

        .file-name:hover {
            color: var(--accent-end);
        }

        .file-details {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.125rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .file-dot {
            width: 3px;
            height: 3px;
            background-color: var(--text-secondary);
            border-radius: 50%;
        }

        .file-actions {
            display: flex;
            gap: 0.5rem;
            flex-shrink: 0;
            margin-left: 0.75rem;
        }

        .btn-action {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background: rgba(31, 41, 55, 0.6);
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-action-copy:hover {
            background-color: rgba(16, 185, 129, 0.1);
            border-color: rgba(16, 185, 129, 0.3);
            color: var(--success-color);
        }

        .btn-action-delete:hover {
            background-color: rgba(239, 68, 68, 0.1);
            border-color: rgba(239, 68, 68, 0.3);
            color: var(--error-color);
        }

        /* Notificações Toasts */
        .toast-container {
            position: fixed;
            bottom: 1.5rem;
            right: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            z-index: 9999;
            pointer-events: none;
        }

        .toast {
            pointer-events: auto;
            background-color: rgba(11, 17, 30, 0.95);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 0.875rem 1.25rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            color: var(--text-primary);
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            min-width: 280px;
            max-width: 380px;
            transform: translateY(20px);
            opacity: 0;
            animation: toastIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        .toast-success {
            border-left: 3px solid var(--success-color);
        }

        .toast-error {
            border-left: 3px solid var(--error-color);
        }

        .toast-info {
            border-left: 3px solid var(--accent-start);
        }

        .toast.fade-out {
            animation: toastOut 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes toastIn {
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }

        @keyframes toastOut {
            to {
                transform: translateY(10px);
                opacity: 0;
            }
        }

        /* Modal Customizado */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background-color: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            z-index: 9998;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
        }

        .modal-overlay.active {
            opacity: 1;
            pointer-events: auto;
        }

        .modal-box {
            background-color: #0b111e;
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.75rem;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.8);
            transform: scale(0.95);
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .modal-overlay.active .modal-box {
            transform: scale(1);
        }

        .modal-title {
            font-size: 1.15rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.75rem;
        }

        .modal-message {
            font-size: 0.875rem;
            color: var(--text-secondary);
            line-height: 1.5;
            margin-bottom: 1.5rem;
        }

        .modal-actions {
            display: flex;
            justify-content: flex-end;
            gap: 0.75rem;
        }

        .btn-modal {
            padding: 0.625rem 1.125rem;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            outline: none;
        }

        .btn-modal-cancel {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
        }

        .btn-modal-cancel:hover {
            background-color: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
            border-color: var(--text-secondary);
        }

        .btn-modal-confirm {
            background-color: var(--error-color);
            border: none;
            color: white;
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.2);
        }

        .btn-modal-confirm:hover {
            background-color: #dc2626;
            box-shadow: 0 6px 16px rgba(239, 68, 68, 0.3);
        }
    </style>
</head>
<body>

<div class="container <?= $isAuthenticated ? 'container-wide' : '' ?>">
    <div class="card">
        
        <?php if (!$isAuthenticated): ?>
            <!-- TELA DE LOGIN -->
            <div class="card-header">
                <h1 class="card-title">Acesso Restrito</h1>
                <p class="card-subtitle">Insira a chave secreta para carregar arquivos</p>
            </div>

            <?php if (!empty($error)): ?>
                <div class="alert alert-error">
                    <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg>
                    <span><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></span>
                </div>
            <?php endif; ?>

            <form action="index.php" method="POST" autocomplete="off">
                <input type="hidden" name="action" value="login">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                
                <!-- Honeypot para detecção de bots (invisível a humanos) -->
                <div style="display:none !important;">
                    <input type="text" name="username" tabindex="-1" autocomplete="off">
                </div>

                <div class="form-group">
                    <label for="password" class="form-label">Chave de Acesso</label>
                    <input type="password" id="password" name="password" class="form-input" placeholder="••••••••••••" required autofocus>
                </div>

                <button type="submit" class="btn">Entrar no Painel</button>
            </form>

        <?php else: ?>
            <!-- Dashboard Layout Grid -->
            <div class="dashboard-grid">
                <!-- Coluna Esquerda: Uploader -->
                <div class="uploader-section">
                    <div class="card-header" style="text-align: left; margin-bottom: 1.5rem;">
                        <h1 class="card-title">Carregar Arquivo</h1>
                        <p class="card-subtitle">Suba arquivos direto para o Cloudflare R2</p>
                    </div>

                    <div id="js-alert" class="alert" style="display: none;"></div>

                    <!-- Dropzone central -->
                    <div class="dropzone" id="dropzone">
                        <svg class="dropzone-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                        </svg>
                        <p class="dropzone-text">
                            <strong>Clique para selecionar</strong> ou arraste o arquivo aqui.<br>
                            <span style="font-size: 0.75rem; color: var(--text-secondary);">
                                Extensões seguras permitidas (incluindo .exe)
                            </span>
                        </p>
                        <input type="file" id="file-input" class="file-input">
                    </div>

                    <!-- Barra de Progresso -->
                    <div class="progress-container" id="progress-container">
                        <div class="progress-header">
                            <span id="file-name">Carregando arquivo...</span>
                            <span id="progress-percent">0%</span>
                        </div>
                        <div class="progress-bar-wrapper">
                            <div class="progress-bar" id="progress-bar"></div>
                        </div>
                    </div>

                    <!-- Resultado com link copiável -->
                    <div class="result-container" id="result-container">
                        <div class="result-title">
                            <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>
                            Link público gerado com sucesso!
                        </div>
                        <div class="copy-group">
                            <input type="text" id="public-url" class="form-input copy-input" readonly>
                            <button class="btn btn-copy" id="btn-copy">Copiar</button>
                        </div>
                    </div>

                    <!-- Campo invisível de Honeypot para upload -->
                    <div style="display:none !important;">
                        <input type="text" id="upload-honeypot" tabindex="-1" autocomplete="off">
                    </div>

                    <a href="index.php?action=logout" class="btn btn-logout">Sair do Painel</a>
                </div>

                <!-- Coluna Direita: Galeria de Arquivos -->
                <div class="gallery-section">
                    <div class="card-header" style="text-align: left; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center; gap: 1rem;">
                        <div>
                            <h2 class="card-title" style="font-size: 1.25rem; margin-bottom: 0.25rem;">Arquivos no Bucket</h2>
                            <p class="card-subtitle">Gerencie os arquivos armazenados no R2</p>
                        </div>
                        <button id="btn-refresh-gallery" class="btn-refresh" title="Atualizar Galeria">
                            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99"></path>
                            </svg>
                        </button>
                    </div>

                    <!-- Barra de pesquisa da galeria -->
                    <div class="search-box">
                        <svg class="search-icon" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                        </svg>
                        <input type="text" id="gallery-search" class="form-input search-input" placeholder="Pesquisar arquivos...">
                    </div>

                    <!-- Lista de arquivos da galeria -->
                    <div class="gallery-list" id="gallery-list">
                        <div class="gallery-empty">Carregando galeria...</div>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php if (!$hasComposer): ?>
            <div class="composer-warning">
                ⚠️ SDK do Cloudflare ausente no servidor. O uploader não funcionará até que dependências sejam instaladas.
            </div>
        <?php endif; ?>
        
    </div>
</div>

<!-- Toast Container para Notificações -->
<div class="toast-container" id="toast-container"></div>

<!-- Modal de Confirmação Customizado para Deleção -->
<div class="modal-overlay" id="confirm-modal">
    <div class="modal-box">
        <h3 class="modal-title">Excluir Arquivo</h3>
        <p class="modal-message">Você tem certeza que deseja excluir permanentemente o arquivo <strong id="modal-file-name" style="color: var(--text-primary); word-break: break-all;"></strong> do Cloudflare R2?</p>
        <div class="modal-actions">
            <button class="btn-modal btn-modal-cancel" id="btn-modal-cancel">Cancelar</button>
            <button class="btn-modal btn-modal-confirm" id="btn-modal-confirm">Sim, Excluir</button>
        </div>
    </div>
</div>

<script>
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressPercent = document.getElementById('progress-percent');
    const fileNameDisplay = document.getElementById('file-name');
    const resultContainer = document.getElementById('result-container');
    const publicUrlInput = document.getElementById('public-url');
    const btnCopy = document.getElementById('btn-copy');
    const jsAlert = document.getElementById('js-alert');

    // Elementos da Galeria e Toasts
    const btnRefreshGallery = document.getElementById('btn-refresh-gallery');
    const gallerySearch = document.getElementById('gallery-search');
    const galleryList = document.getElementById('gallery-list');
    const confirmModal = document.getElementById('confirm-modal');
    const modalFileName = document.getElementById('modal-file-name');
    const btnModalCancel = document.getElementById('btn-modal-cancel');
    const btnModalConfirm = document.getElementById('btn-modal-confirm');
    const toastContainer = document.getElementById('toast-container');

    if (dropzone && fileInput) {
        const csrfToken = "<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>";

        dropzone.addEventListener('click', () => fileInput.click());

        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.add('dragover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.remove('dragover');
            }, false);
        });

        dropzone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                handleUpload(files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (fileInput.files.length > 0) {
                handleUpload(fileInput.files[0]);
            }
        });

        // Fluxo de Upload Direto via Presigned URL
        function handleUpload(file) {
            resultContainer.style.display = 'none';
            showAlert('none');

            // 1. Obter a URL pré-assinada do backend PHP
            fileNameDisplay.textContent = "Preparando conexao segura...";
            progressPercent.textContent = '0%';
            progressBar.style.width = '0%';
            progressContainer.style.display = 'block';

            const mimeType = file.type || 'application/octet-stream';
            const honeypotVal = document.getElementById('upload-honeypot').value;

            // Solicitação de assinatura
            fetch('index.php?action=get_presigned_url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    fileName: file.name,
                    fileSize: file.size,
                    mimeType: mimeType,
                    csrf_token: csrfToken,
                    upload_honeypot: honeypotVal
                })
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => { throw new Error(err.error || 'Erro ao gerar assinatura de upload.'); });
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // Executar o upload direto PUT para o Cloudflare R2
                    executeDirectUpload(file, data.presignedUrl, data.publicUrl, mimeType, data.contentDisposition);
                } else {
                    throw new Error('Assinatura recusada pelo servidor.');
                }
            })
            .catch(error => {
                progressContainer.style.display = 'none';
                showAlert('error', error.message || 'Falha de comunicacao com o servidor.');
            });
        }

        // Realizar o envio PUT direto do navegador para o Cloudflare R2
        function executeDirectUpload(file, presignedUrl, publicUrl, mimeType, contentDisposition) {
            fileNameDisplay.textContent = "Enviando diretamente ao Cloudflare R2: " + file.name;
            
            const xhr = new XMLHttpRequest();
            xhr.open('PUT', presignedUrl, true);
            
            // ATENÇÃO: O Content-Type DEVE coincidir exatamente com o que foi assinado no PHP
            xhr.setRequestHeader('Content-Type', mimeType);
            xhr.setRequestHeader('Content-Disposition', contentDisposition);

            // Acompanhamento do progresso de upload
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    progressBar.style.width = percent + '%';
                    progressPercent.textContent = percent + '%';
                }
            });

            xhr.onload = function() {
                progressContainer.style.display = 'none';
                // O Cloudflare R2 retorna HTTP 200 para uploads PUT bem sucedidos
                if (xhr.status === 200 || xhr.status === 201) {
                    publicUrlInput.value = publicUrl;
                    resultContainer.style.display = 'block';
                    showAlert('success', 'Upload concluido com sucesso!');
                    loadGallery(); // Atualizar galeria pós-upload
                } else {
                    showAlert('error', 'Falha no envio direto ao R2 (HTTP ' + xhr.status + ').');
                }
            };

            xhr.onerror = function() {
                progressContainer.style.display = 'none';
                showAlert('error', 'Erro de conexao direta com o Cloudflare R2.');
            };

            // Enviar os bytes puros do arquivo
            xhr.send(file);
        }

        // Sistema de Cópia do Link do Uploader Principal
        btnCopy.addEventListener('click', () => {
            publicUrlInput.select();
            publicUrlInput.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(publicUrlInput.value)
                .then(() => {
                    btnCopy.textContent = 'Copiado!';
                    btnCopy.classList.add('success');
                    showToast('Link público copiado com sucesso!', 'success');
                    setTimeout(() => {
                        btnCopy.textContent = 'Copiar';
                        btnCopy.classList.remove('success');
                    }, 2000);
                })
                .catch(() => {
                    showAlert('error', 'Nao foi possivel copiar automaticamente.');
                    showToast('Erro ao copiar link.', 'error');
                });
        });

        function showAlert(type, text = '') {
            jsAlert.className = 'alert';
            if (type === 'none') {
                jsAlert.style.display = 'none';
                return;
            }
            jsAlert.style.display = 'flex';
            jsAlert.classList.add('alert-' + type);
            
            let iconSvg = '';
            if (type === 'success') {
                iconSvg = '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>';
            } else {
                iconSvg = '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg>';
            }
            
            jsAlert.innerHTML = iconSvg + '<span>' + text + '</span>';
        }

        // --- SISTEMA DE TOASTS ---
        function showToast(message, type = 'success') {
            if (!toastContainer) return;
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            
            let iconSvg = '';
            if (type === 'success') {
                iconSvg = `<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>`;
            } else if (type === 'error') {
                iconSvg = `<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg>`;
            } else {
                iconSvg = `<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2z"/></svg>`;
            }
            
            toast.innerHTML = `${iconSvg}<span>${message}</span>`;
            toastContainer.appendChild(toast);
            
            setTimeout(() => {
                toast.classList.add('fade-out');
                toast.addEventListener('animationend', () => {
                    toast.remove();
                });
            }, 3500);
        }

        // --- SISTEMA DA GALERIA ---
        let allFiles = [];
        let fileToDelete = null;

        function loadGallery() {
            if (!galleryList) return;
            
            if (btnRefreshGallery) {
                btnRefreshGallery.classList.add('spinning');
            }
            
            fetch('index.php?action=list_files')
                .then(response => {
                    if (!response.ok) throw new Error('Falha ao obter lista de arquivos.');
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        allFiles = data.files || [];
                        renderGallery(allFiles);
                    } else {
                        throw new Error(data.error || 'Erro desconhecido ao carregar galeria.');
                    }
                })
                .catch(error => {
                    galleryList.innerHTML = `<div class="gallery-empty" style="color: var(--error-color); border-color: rgba(239, 68, 68, 0.2);">
                        ⚠️ Falha ao carregar galeria: ${error.message}
                    </div>`;
                    showToast('Erro ao carregar arquivos da galeria.', 'error');
                })
                .finally(() => {
                    if (btnRefreshGallery) {
                        setTimeout(() => btnRefreshGallery.classList.remove('spinning'), 300);
                    }
                });
        }

        function renderGallery(files) {
            if (!galleryList) return;
            
            if (files.length === 0) {
                galleryList.innerHTML = '<div class="gallery-empty">Nenhum arquivo encontrado no bucket R2.</div>';
                return;
            }
            
            galleryList.innerHTML = '';
            
            files.forEach(file => {
                const item = document.createElement('div');
                item.className = 'file-item';
                
                const ext = file.key.split('.').pop().toLowerCase();
                let iconHtml = '';
                const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext);
                
                if (isImage) {
                    iconHtml = `<img src="${file.url}" class="file-icon-img" alt="" loading="lazy" onerror="this.outerHTML='🖼️'">`;
                } else {
                    switch(ext) {
                        case 'pdf': iconHtml = '📄'; break;
                        case 'zip':
                        case 'rar':
                        case '7z': iconHtml = '📦'; break;
                        case 'exe': iconHtml = '⚙️'; break;
                        case 'mp4': iconHtml = '🎥'; break;
                        case 'txt':
                        case 'csv': iconHtml = '📝'; break;
                        default: iconHtml = '📎';
                    }
                }
                
                item.innerHTML = `
                    <div class="file-info">
                        <div class="file-icon">${iconHtml}</div>
                        <div class="file-meta">
                            <a href="${file.url}" target="_blank" class="file-name" title="${file.key}">${file.key}</a>
                            <div class="file-details">
                                <span>${file.size}</span>
                                <span class="file-dot"></span>
                                <span>${new Date(file.last_modified * 1000).toLocaleDateString('pt-BR')}</span>
                            </div>
                        </div>
                    </div>
                    <div class="file-actions">
                        <button class="btn-action btn-action-copy" data-url="${file.url}" title="Copiar Link">
                            <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 002 2h2a2 2 0 002-2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path>
                            </svg>
                        </button>
                        <button class="btn-action btn-action-delete" data-key="${encodeURIComponent(file.key)}" data-display-key="${file.key}" title="Excluir Arquivo">
                            <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                            </svg>
                        </button>
                    </div>
                `;
                
                // Evento de Cópia
                item.querySelector('.btn-action-copy').addEventListener('click', (e) => {
                    const button = e.currentTarget;
                    const url = button.getAttribute('data-url');
                    navigator.clipboard.writeText(url)
                        .then(() => {
                            showToast('Link copiado com sucesso!', 'success');
                            button.style.color = 'var(--success-color)';
                            button.style.borderColor = 'rgba(16, 185, 129, 0.3)';
                            setTimeout(() => {
                                button.style.color = '';
                                button.style.borderColor = '';
                            }, 2000);
                        })
                        .catch(() => showToast('Erro ao copiar link.', 'error'));
                });
                
                // Evento de Deleção
                item.querySelector('.btn-action-delete').addEventListener('click', (e) => {
                    const key = decodeURIComponent(e.currentTarget.getAttribute('data-key'));
                    openDeleteModal(key);
                });
                
                galleryList.appendChild(item);
            });
        }

        // --- SISTEMA DE CONFIRMAÇÃO DE EXCLUSÃO ---
        function openDeleteModal(key) {
            fileToDelete = key;
            if (modalFileName) modalFileName.textContent = key;
            if (confirmModal) confirmModal.classList.add('active');
        }

        function closeDeleteModal() {
            fileToDelete = null;
            if (confirmModal) confirmModal.classList.remove('active');
        }

        if (btnModalCancel) {
            btnModalCancel.addEventListener('click', closeDeleteModal);
        }

        if (confirmModal) {
            confirmModal.addEventListener('click', (e) => {
                if (e.target === confirmModal) closeDeleteModal();
            });
        }

        if (btnModalConfirm) {
            btnModalConfirm.addEventListener('click', () => {
                if (!fileToDelete) return;
                
                btnModalConfirm.disabled = true;
                btnModalConfirm.textContent = 'Excluindo...';
                
                fetch('index.php?action=delete_file', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({
                        key: fileToDelete,
                        csrf_token: csrfToken
                    })
                })
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(err => { throw new Error(err.error || 'Erro ao excluir o arquivo.'); });
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        showToast('Arquivo excluído com sucesso!', 'success');
                        loadGallery();
                    } else {
                        throw new Error('Falha na deleção.');
                    }
                })
                .catch(error => {
                    showToast(error.message || 'Falha ao deletar arquivo.', 'error');
                })
                .finally(() => {
                    btnModalConfirm.disabled = false;
                    btnModalConfirm.textContent = 'Sim, Excluir';
                    closeDeleteModal();
                });
            });
        }

        // --- SISTEMA DE PESQUISA E ATUALIZAÇÃO ---
        if (gallerySearch) {
            gallerySearch.addEventListener('input', (e) => {
                const query = e.target.value.toLowerCase().trim();
                if (query === '') {
                    renderGallery(allFiles);
                } else {
                    const filtered = allFiles.filter(file => file.key.toLowerCase().includes(query));
                    renderGallery(filtered);
                }
            });
        }

        if (btnRefreshGallery) {
            btnRefreshGallery.addEventListener('click', loadGallery);
        }

        // Carregar galeria no início
        loadGallery();
    }
</script>

</body>
</html>
