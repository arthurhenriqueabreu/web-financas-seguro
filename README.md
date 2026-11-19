# Raiz — finanças em família

Aplicação web de controle de finanças pessoais, desenvolvida para a disciplina de Codificação Segura. O responsável cria a conta, registra receitas e despesas, anexa comprovantes e acompanha saldo e histórico. Ele também pode criar contas de filhos e decidir, individualmente, se cada conta pode ver o histórico e registrar lançamentos. Os lançamentos pertencem à família, e cada família fica isolada das demais.

## Tecnologias

- **Back-end:** Node.js 22.13+ (recomendado: 24) e Express 5.
- **Banco de dados:** SQLite pelo módulo nativo `node:sqlite` (em Node 22 e 24 aparece um aviso de recurso experimental, que é normal).
- **Front-end:** HTML, CSS e JavaScript puro, sem framework.
- **Bibliotecas:** `bcryptjs` (hash de senha), `multer` (upload), `helmet` (cabeçalhos HTTP e CSP) e `express-rate-limit` (limite de requisições).
- **Testes:** executor nativo `node:test`.

## Como rodar localmente

1. Instale o [Node.js](https://nodejs.org/) 22.13 ou superior.
2. Na pasta do projeto, execute:

   ```bash
   npm ci
   npm start
   ```

3. Abra `http://localhost:3000`, clique em **Criar conta** e cadastre o responsável (senha de 12 a 128 caracteres).

O banco é criado automaticamente em `data/financas.sqlite`. Essa pasta está no `.gitignore` e não deve ser publicada.

Outros comandos:

| Comando | O que faz |
| --- | --- |
| `npm run dev` | Inicia o servidor reiniciando a cada alteração |
| `npm test` | Executa os testes automatizados |
| `npm audit --omit=dev` | Procura vulnerabilidades conhecidas nas dependências |

Variáveis de ambiente (veja `.env.example`; a aplicação **não** carrega o arquivo `.env` sozinha, defina-as no terminal):

| Variável | Padrão | Descrição |
| --- | --- | --- |
| `PORT` | `3000` | Porta do servidor |
| `DB_PATH` | `data/financas.sqlite` | Caminho do arquivo do banco |
| `NODE_ENV` | — | Use `production` em produção (ativa cookie `Secure` e prefixo `__Host-`) |
| `TRUST_PROXY` | `0` | Use `1` apenas atrás de um proxy confiável |

Exemplo: `PORT=8080 npm start`.

## Funcionalidades

- Cadastro, login e logout.
- Receitas e despesas com data, descrição, categoria e valor (armazenado em centavos).
- Saldo total, entradas, saídas e **total por categoria**.
- Histórico com filtros por mês, tipo e categoria.
- Categorias iniciais e criação de novas categorias pelo responsável.
- Comprovante (cupom fiscal) em PDF, PNG, JPEG ou WebP de até 5 MB, acessível só por usuários autorizados da família.
- **Controle parental:** o responsável cria contas de filhos e define, para cada uma, as permissões "ver saldo e histórico" e "registrar lançamentos". Também pode redefinir a senha de um filho (as sessões dele são encerradas), remover a conta (os lançamentos permanecem na família) e excluir lançamentos. Filhos não gerenciam contas, categorias nem permissões.

## Segurança

| Risco | Como é tratado |
| --- | --- |
| **Hardcoded SQL / SQL Injection** | Toda entrada de usuário chega ao SQLite por parâmetros `?` em consultas preparadas. Os únicos trechos SQL montados dinamicamente (filtros do histórico) usam condições fixas no código, depois de validar os valores recebidos. |
| **XSS** | O front-end insere dados com `textContent` e criação de nós DOM, nunca com `innerHTML`. A CSP (via `helmet`) limita scripts, estilos e imagens à própria origem e bloqueia `object-src`. |
| **CSRF** | Rotas que alteram dados exigem token CSRF vinculado à sessão no cabeçalho `x-csrf-token`. A API também rejeita `Origin` diferente do host (inclusive em login e cadastro) e requisições `cross-site`. Cookie com `SameSite=Strict`. |
| **Mass assignment** | Cada rota lê explicitamente só os campos aceitos. `owner_id`, `parent_id`, `created_by` e as permissões são definidos pelo servidor, nunca pelo corpo da requisição. |
| **Session hijacking / fixação de sessão** | Token aleatório de 256 bits, guardado no banco apenas como hash SHA-256. Expiração de 7 dias, sessão nova no login e no cadastro, invalidação no logout, limpeza periódica de sessões expiradas. Cookie `HttpOnly` e `SameSite=Strict`; em produção também `Secure` e prefixo `__Host-`. |
| **Autenticação e força bruta** | Senhas com bcrypt (custo 12), mínimo de 12 caracteres. Limite de 15 tentativas por IP a cada 15 minutos em login e cadastro, e de 600 requisições por IP a cada 15 minutos na API. O login faz uma comparação falsa quando o e-mail não existe, para igualar o tempo de resposta. |
| **Controle de acesso (IDOR)** | Cada consulta, download e exclusão filtra pela família do usuário. As permissões dos filhos são lidas do banco a cada requisição, então mudanças valem imediatamente. |
| **Upload malicioso** | Limite de 5 MB e um arquivo por envio. O tipo é conferido pela assinatura dos bytes e precisa coincidir com o informado. SVG e HTML são recusados. Os arquivos ficam no banco, fora da pasta pública, e são baixados como `attachment` com `X-Content-Type-Options: nosniff`. |
| **Validação de entrada** | Tipos, tamanhos, e-mail, valores, datas, categorias e filtros são validados no servidor. Valores monetários são inteiros em centavos. Corpos JSON limitados a 32 KB. |

### Limitações conhecidas

- O cadastro informa quando o e-mail já existe, o que permite descobrir e-mails cadastrados. Evitar isso exigiria confirmação por e-mail.
- Não há recuperação de senha do responsável, autenticação em dois fatores nem registro de auditoria.
- Não há edição de lançamentos nem exclusão de categorias.

### Para uso em produção

Use `NODE_ENV=production`, coloque a aplicação atrás de **HTTPS** e defina `TRUST_PROXY=1` apenas se houver um proxy confiável à frente. Faça backup do arquivo SQLite, restrinja o acesso à pasta `data/` e rode `npm audit` com frequência.

## Testes

`npm test` cobre:

- cadastro, saldo e lançamentos;
- filtro e total por categoria;
- isolamento entre famílias;
- token CSRF e rejeição de origem externa;
- tentativa de mass assignment;
- upload inválido;
- permissões dos filhos, troca de senha, remoção de conta e tentativa de acesso por outro responsável;
- exclusão de lançamentos e logout.

## Estrutura do projeto

```
src/server.js           rotas, autenticação, sessões e validações
src/db.js               criação do banco e tabelas
public/                 interface (index.html, app.js, style.css)
test/                   testes automatizados
.env.example            variáveis de ambiente documentadas
```