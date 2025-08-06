# SSL Certificate Template

Este diretório deve conter o certificado SSL para conexão com Redis Square Cloud.

## 📋 Como configurar:

1. **Obtenha o certificado** da Square Cloud:

   - Acesse o painel da Square Cloud
   - Vá para configurações do banco Redis
   - Baixe o arquivo `certificate.pem`

2. **Coloque o arquivo aqui**:

   ```
   app/redis/ssl/certificate.pem
   ```

3. **Formato esperado**:
   ```
   -----BEGIN PRIVATE KEY-----
   [sua chave privada aqui]
   -----END PRIVATE KEY-----
   -----BEGIN CERTIFICATE-----
   [seu certificado aqui]
   -----END CERTIFICATE-----
   ```

## ⚠️ **IMPORTANTE**:

- **NUNCA** commite certificados no Git
- O arquivo `certificate.pem` está no `.gitignore`
- Cada desenvolvedor deve configurar seu próprio certificado
- Em produção, use variáveis de ambiente ou secrets manager
