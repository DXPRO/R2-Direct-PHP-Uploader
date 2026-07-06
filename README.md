# R2 Direct PHP Uploader

Uma aplicação leve, segura e moderna em PHP (8.2+) projetada para realizar upload de arquivos de grande porte (incluindo instaladores `.exe`, arquivos compactados `.zip`, PDFs e mídias) **diretamente do navegador do usuário para o Cloudflare R2**.

O projeto utiliza a arquitetura de **Presigned URLs (URLs Pré-assinadas S3v4)**. Isso significa que o servidor PHP local apenas assina digitalmente a transação, e o navegador realiza a transferência dos bytes diretamente aos servidores globais do Cloudflare. 

### 🏆 Por que usar esta arquitetura?
* **Sem limites de timeout**: Arquivos grandes de 25MB, 100MB ou mais são enviados sem sofrer interrupção por limite de tempo de execução do PHP (`max_execution_time`) em hospedagens compartilhadas.
* **Economia extrema de recursos**: O servidor da sua hospedagem (como a [Hostinger](https://www.hostinger.com/br?REFERRALCODE=GWOADMDIGPTD)) não processa a banda e a memória dos arquivos enviados, reduzindo drasticamente o consumo de CPU.
* **Velocidade de transferência superior**: O navegador do usuário envia os bytes para o data center mais próximo da rede de borda do Cloudflare.
* **Segurança mantida**: O bucket R2 permanece privado. O upload só é autorizado se o usuário passar pela tela de autenticação protegida do painel, que gera o link temporário de upload de forma restrita.

---

## 🚀 Funcionalidades
- **Painel Dark Mode**: Interface responsiva e elegante com design moderno (Glassmorphism e fontes otimizadas).
- **Autenticação Segura**: Login protegido por hash criptográfico Bcrypt contra ataques de brute-force e timing attacks.
- **Proteção Antirrobôs**: Tokens CSRF para validação de requisições e campo oculto Honeypot contra spam de formulários.
- **Forçar Download de Executáveis**: Arquivos `.exe` são salvos com cabeçalhos HTTP `Content-Disposition: attachment` para download forçado imediato no cliente final.
- **Segurança de Servidor**: Configurações robustas em `.htaccess` que bloqueiam leitura externa de arquivos sensíveis (`env.php`, logs e chaves) e evitam interrupções no servidor LiteSpeed.
- **Anti-Indexação**: Cabeçalhos HTTP e arquivo `robots.txt` impedem que mecanismos de busca (como Google) rastreiem a página.
- **Logs de Auditoria**: Sistema interno de logs (`uploader.log`) ativável para registro de conexões e geração de assinaturas.

---

## 📋 Requisitos
* Servidor Web (Apache, Nginx ou LiteSpeed/[Hostinger](https://www.hostinger.com/br?REFERRALCODE=GWOADMDIGPTD))
* PHP 8.2 ou superior
* Extensões PHP `curl` e `openssl` ativadas
* Composer instalado (para gerenciamento de dependências)

---

## 🛠️ Instalação Passo a Passo

### Passo 1: Baixar o Projeto
Baixe os arquivos do projeto e extraia na pasta do seu servidor (por exemplo, na pasta `/public_html/configs/upload/` na [Hostinger](https://www.hostinger.com/br?REFERRALCODE=GWOADMDIGPTD)).

### Passo 2: Instalar as Dependências (Pasta `vendor`)
Abra o terminal do seu computador na pasta raiz do projeto e execute o comando abaixo para baixar o SDK oficial da AWS para PHP e gerar a pasta `vendor/`:
```bash
composer install
```
*Se você estiver usando uma hospedagem sem acesso SSH/Terminal:*
1. Execute o comando `composer install` localmente em sua máquina.
2. Compacte a pasta `vendor/` gerada em um arquivo `vendor.zip`.
3. Suba o arquivo `vendor.zip` para o gerenciador de arquivos da [Hostinger](https://www.hostinger.com/br?REFERRALCODE=GWOADMDIGPTD) e extraia-o na mesma pasta do arquivo `index.php`.

### Passo 3: Configurar as Credenciais
1. Na raiz do projeto, faça uma cópia do arquivo `env.example.php` e renomeie-o para **`env.php`**.
2. Abra o arquivo `env.php` e configure seus dados de acesso (veja o guia do Cloudflare abaixo).

### Passo 4: Criar a Senha do Painel
A senha é armazenada como um hash seguro Bcrypt. Para definir sua própria senha:
1. No terminal do seu computador (ou ferramenta interativa), rode o comando abaixo substituindo `sua_senha_secreta` pela senha que deseja usar no painel:
   ```bash
   php -r "echo password_hash('sua_senha_secreta', PASSWORD_BCRYPT);"
   ```
2. O terminal gerará uma linha de caracteres (ex: `$2y$10$...`). Copie este código gerado por inteiro.
3. No seu arquivo `env.php`, cole esse código no campo `'UPLOAD_PASSWORD_HASH'`.

---

## ☁️ Guia de Configuração no Cloudflare R2

Siga os passos abaixo para configurar a sua conta do Cloudflare R2 e preencher o `env.php`:

### 1. Criar o Bucket no Cloudflare
1. Acesse o seu painel do Cloudflare e clique em **R2** na barra lateral esquerda.
2. Clique no botão **Criar Bucket** (*Create Bucket*).
3. Defina um nome para o bucket (ex: `meu-bucket-instaladores`) e clique em criar.
4. Anote o nome do bucket e coloque no campo `'R2_BUCKET_NAME'` do seu `env.php`.

### 2. Obter o Account ID
1. Na página inicial do **R2** (onde você visualiza a lista de buckets), localize o campo **ID da Conta** (*Account ID*) localizado na barra lateral direita.
2. Copie essa sequência de caracteres e cole no campo `'R2_ACCOUNT_ID'` no `env.php`.

### 3. Gerar o Token de API (Chaves S3)
1. Na página inicial do **R2**, clique em **Gerenciar tokens de API do R2** (*Manage R2 API Tokens*) no canto superior direito.
2. Clique em **Criar Token de API** (*Create API Token*).
3. Configure o token da seguinte forma:
   * **Nome do Token**: Defina um nome identificável (ex: *Uploader Token*).
   * **Permissões**: Escolha a opção **Editar** (*Edit*) ou **Leitura e Gravação** (*Read & Write*).
   * **Escopo**: Selecione "Todos os buckets" ou aponte especificamente para o bucket que você criou.
4. Clique em **Criar Token**.
5. Na próxima tela, o Cloudflare exibirá as credenciais de acesso S3. **Importante:** Copie esses valores imediatamente, pois eles não serão exibidos novamente!
   * **ID da Chave de Acesso** (*Access Key ID*): Cole no campo `'R2_ACCESS_KEY'` no `env.php`.
   * **Chave de Acesso Secreta** (*Secret Access Key*): Cole no campo `'R2_SECRET_KEY'` no `env.php`.

### 4. Ativar a URL Pública
Para obter o link de download após os uploads, você precisa ativar a exibição pública do bucket:
1. Abra o seu bucket recém-criado no painel do Cloudflare e clique na aba **Configurações** (*Settings*).
2. Na seção **Acesso Público** (*Public Access*), clique em **Ativar URL de Desenvolvimento Público** (*Allow Access*).
3. Copie o domínio gerado (ex: `https://pub-xxxxxxxxxxxxxx.r2.dev`) e cole no campo `'R2_PUBLIC_URL'` no `env.php`.
   * *(Opcional: Você pode conectar um domínio customizado próprio clicando em "Conectar Domínio" nesta mesma tela).*

### 5. Configurar a Política de CORS (Obrigatório)
Como o navegador enviará arquivos diretamente para o Cloudflare via JavaScript (Cross-Origin), precisamos liberar a permissão de CORS no R2:
1. Ainda na aba **Configurações** do seu bucket, desça até encontrar a seção **Política de CORS** (*CORS Policy*).
2. Clique no botão **Adicionar** (*Add CORS Policy*).
3. Cole o seguinte JSON de configuração:
   ```json
   [
     {
       "AllowedOrigins": [
         "*"
       ],
       "AllowedMethods": [
         "PUT",
         "GET",
         "HEAD"
       ],
       "AllowedHeaders": [
         "*"
       ],
       "ExposeHeaders": []
     }
   ]
   ```
   *Se quiser segurança máxima restringindo para que apenas o seu domínio faça envios, altere o `"*"` em `"AllowedOrigins"` para a URL do seu site (ex: `"https://meu-site-uploader.com"`).*
 4. Clique em **Salvar**.

---

## 🔒 Configurações do Servidor (Segurança LiteSpeed/[Hostinger](https://www.hostinger.com/br?REFERRALCODE=GWOADMDIGPTD))
O arquivo `.htaccess` fornecido no projeto já está pré-configurado para:
- Forçar tráfego HTTPS em todas as conexões.
- Bloquear a leitura direta de qualquer arquivo `.php` auxiliar (como o `env.php`), arquivos `.json`, logs e documentações markdown por usuários maliciosos.
- Desativar a listagem visual de pastas do servidor (`Options -Indexes`).
- Configurar as variáveis `noabort` e `noconntimeout` no LiteSpeed, impedindo que o servidor [Hostinger](https://www.hostinger.com/br?REFERRALCODE=GWOADMDIGPTD) encerre a requisição HTTP enquanto o navegador realiza uploads.
