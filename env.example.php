<?php
/**
 * Arquivo de Exemplo de Configuração - env.example.php
 * Copie este arquivo como "env.php" no seu servidor e preencha com os seus dados.
 */

if (basename($_SERVER['SCRIPT_FILENAME']) === 'env.example.php') {
    header('HTTP/1.1 403 Forbidden');
    exit('Acesso negado.');
}

return [
    // Hash da senha de upload (Bcrypt)
    // Para gerar um novo hash de senha, execute no terminal: 
    // php -r "echo password_hash('sua_senha_aqui', PASSWORD_BCRYPT);"
    // O hash padrão abaixo corresponde a senha padrão: 'r2uploader123'
    'UPLOAD_PASSWORD_HASH' => '$2y$10$t2Bf6P25jH.r5b5WwKNuEerKjXfH1oKk8qHk7p5hM2m3V1b4wPqOm',

    // Configurações do Cloudflare R2
    // ID da Conta do Cloudflare (encontrado na barra lateral direita da página do R2)
    'R2_ACCOUNT_ID' => 'seu_account_id_aqui',
    
    // Credenciais do Token de API S3 gerado no R2
    'R2_ACCESS_KEY' => 'sua_access_key_aqui',
    'R2_SECRET_KEY' => 'sua_secret_key_aqui',
    
    // Nome do bucket R2 onde os arquivos serão salvos
    'R2_BUCKET_NAME' => 'seu_nome_de_bucket_aqui',
    
    // URL Pública para downloads (URL de desenvolvimento .r2.dev ou seu subdomínio customizado)
    // Exemplo: https://pub-xxxxxxxxxxxxxx.r2.dev
    'R2_PUBLIC_URL' => 'https://sua_url_publica_do_bucket.r2.dev',

    // Configurações do App
    // 'production' oculta erros fatais do PHP do usuário final.
    // 'development' exibe os erros detalhados (útil para depuração).
    'APP_ENV' => 'production', 
    
    // Habilita (true) ou desabilita (false) o arquivo de log local 'uploader.log'
    'ENABLE_DEBUG_LOG' => true,
];
