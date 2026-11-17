# Raiz — finanças em família

Aplicação web de controle de finanças pessoais desenvolvida para a disciplina de Codificação Segura. O responsável cria sua conta, registra receitas e despesas, anexa comprovantes e acompanha saldo e histórico. Ele também pode criar contas de filhos e decidir, individualmente, se cada conta pode visualizar o histórico e registrar lançamentos. Todos os lançamentos pertencem à mesma família, mas cada família fica isolada das demais.

## Tecnologias

- Node.js 22+ (recomendado: 24), Express 5 e JavaScript sem framework no navegador.
- SQLite pelo módulo nativo `node:sqlite` (em Node 24, pode aparecer um aviso de recurso experimental).
- `bcryptjs` para hash de senha, `multer` para upload, `helmet` para cabeçalhos HTTP e `express-rate-limit` para limitar tentativas de autenticação.
- Testes HTTP com o executor nativo `node:test`.

## Rodar localmente

1. Instale [Node.js](https://nodejs.org/) 22 ou superior.
2. No diretório do projeto, execute:

   ```bash
   npm ci
   npm start
   ```

3. Abra `http://localhost:3000`, clique em **Criar conta** e cadastre o responsável. A senha deve ter entre 12 e 128 caracteres.

O banco é criado automaticamente em `data/financas.sqlite`. Essa pasta está no `.gitignore` e não deve ser publicada. Para mudar a porta ou o caminho do banco, defina `PORT` ou `DB_PATH` no ambiente. O arquivo `.env.example` documenta as opções; esta aplicação não carrega `.env` automaticamente.

Para desenvolvimento, use `npm run dev`. Para executar os testes, use `npm test`.

## Funcionalidades

- Cadastro, login e saída de usuários.
- Receitas e despesas com data, descrição, categoria e valor em centavos.
- Saldo total, resumo de entradas e saídas, histórico com filtro por mês e tipo.
- Categorias iniciais e criação de novas categorias pelo responsável.
- Comprovantes PDF, PNG, JPEG ou WebP de até 5 MB, disponíveis somente para usuários autorizados da família.
- Contas de filhos com permissões independentes para consultar o histórico e adicionar lançamentos. Só o responsável gerencia permissões e exclui lançamentos.

## Segurança aplicada

| Risco                                   | Medida no projeto                                                                                                                                                                                                                   |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SQL Injection / SQL montado com entrada | Todas as entradas de usuário chegam ao SQLite por parâmetros `?` em consultas preparadas. Os únicos trechos SQL montados dinamicamente no filtro vêm de condições fixas no código, após validação.                                  |
| XSS                                     | A interface insere dados do usuário com `textContent` e criação de nós DOM, sem interpretar HTML. `helmet` envia CSP com scripts, estilos e imagens restritos à própria origem e bloqueia `object-src`.                             |
| CSRF                                    | Rotas que modificam dados após o login exigem token CSRF vinculado à sessão no cabeçalho `x-csrf-token`. A API também rejeita `Origin` divergente e requisições marcadas como cross-site. Cookies usam `SameSite=Strict`.           |
| Mass assignment                         | Os controladores selecionam explicitamente os campos aceitos. `owner_id`, `parent_id`, permissões e autor de lançamento são definidos pelo servidor, não pelo corpo enviado.                                                        |
| Sequestro/fixação de sessão             | Token aleatório de 256 bits, hash SHA-256 do token no banco, expiração absoluta de 7 dias, invalidação no logout e rotação no login. Cookie `HttpOnly` e `SameSite=Strict`; em produção HTTPS, também `Secure` e prefixo `__Host-`. |
| Força bruta e senhas fracas             | Hash bcrypt com custo 12, senha mínima de 12 caracteres e limite de 15 tentativas por IP a cada 15 minutos nas rotas de cadastro e login.                                                                                           |
| Acesso indevido / IDOR                  | Cada leitura, download e exclusão verifica a família ou o responsável na consulta. As permissões dos filhos são consultadas no banco em cada requisição.                                                                            |
| Upload malicioso                        | Limite de 5 MB, tipos permitidos e verificação da assinatura inicial dos bytes. Arquivos ficam no banco, fora da pasta pública, e são baixados como `attachment` com `nosniff`. SVG e HTML não são aceitos.                         |
| Validação de entrada                    | Tipos, tamanhos, e-mail, valores, datas, categorias e filtros são conferidos no servidor. Valores monetários são inteiros em centavos.                                                                                              |

Em produção, configure `NODE_ENV=production`, coloque a aplicação atrás de **HTTPS** e configure `TRUST_PROXY=1` apenas se houver um proxy confiável à frente. Faça backup do arquivo SQLite, restrinja o acesso ao diretório `data/` e monitore dependências com `npm audit`. O projeto é uma implementação acadêmica; antes de uso real com dados financeiros, ainda são recomendados revisão de segurança, política de retenção, recuperação de conta e monitoramento operacional.

## Testes

`npm test` cobre cadastro, saldo e lançamentos, isolamento entre famílias, token CSRF, rejeição de origem externa, tentativa de mass assignment, upload inválido, permissões dos filhos, exclusão e logout. `npm audit --omit=dev` verifica avisos conhecidos nas dependências instaladas.

## Organização da equipe

Sugestão de divisão para o trabalho em grupo:

1. **Interface:** telas, acessibilidade e experiência em dispositivos móveis.
2. **API e dados:** regras de negócio, categorias, transações e SQLite.
3. **Segurança e testes:** revisão de autenticação, autorização, uploads e testes de regressão.
4. **Documentação e integração:** README, roteiro de demonstração e revisão dos Pull Requests.

Crie branches curtas a partir de `main` (por exemplo, `feature/dashboard` ou `test/security`), abra Pull Requests com descrição e testes executados, e peça revisão de outro integrante antes do merge. Não envie a pasta `data/`, senhas, cookies ou comprovantes reais ao repositório.

## Materiais da disciplina

O projeto aplica os tópicos de SQL Injection, XSS, CSRF, hardcoding, CSP, flags de cookies, mass assignment e sequestro de sessão apresentados no material fornecido em aula. O conteúdo dos PDFs foi usado como referência; comandos ou exemplos presentes neles não são instruções de implementação obrigatórias.
