Caso 1: Retorno sem cookie temporário
Preparação: Início do processo de login numa janela normal até à página de autenticação do provedor. Cópia do URL de autorização para uma janela anónima que não possuía o cookie de transação __Host-oauth-tx.

Pedido enviado: Acesso direto à rota de retorno (/oauth/callback/...) com o código de autorização nessa segunda janela.

Resultado esperado: A rota de retorno deverá recusar a resposta por ausência do cookie temporário de segurança e abster-se de criar uma sessão.

Resultado observado: O servidor detetou a falta do cookie restrito, abortou o fluxo de validação e recusou o pedido com sucesso, impedindo a criação da sessão.

Caso 2: State alterado
Preparação: Início de um novo fluxo de login, parando na página do provedor antes de introduzir as credenciais. Na barra de endereços, alteração propositada de um único carater do parâmetro state antes de prosseguir.

Pedido enviado: Submissão do pedido de retorno com o parâmetro state adulterado.

Resultado esperado: A rota de retorno deverá recusar a resposta e interromper o processo antes de efetuar a troca do código de autorização pelo token.

Resultado observado: A verificação de integridade detetou a incompatibilidade no token de estado (mecanismo de proteção contra CSRF), resultando na rejeição imediata do pedido.

Caso 3: Reutilização da transação
Preparação: Conclusão bem-sucedida de um processo de login. Localização da requisição de retorno (callback) no painel Network das ferramentas de desenvolvimento e cópia do respetivo URL.

Pedido enviado: Tentativa de aceder novamente ao URL exato de callback copiado numa nova aba.

Resultado esperado: Como o token de transação e o código já tinham sido consumidos e removidos do armazenamento, a repetição deverá falhar.

Resultado observado: O sistema recusou o pedido por transação inválida ou já utilizada, prevenindo com sucesso ataques de repetição (replay attacks).

Caso 4: Sessão expirada
Preparação: Criação de uma sessão de teste válida na aplicação. Acesso direto à consola da base de dados Cloudflare D1 do laboratório para executar a alteração de validade: UPDATE sessions SET expires_at = 0;.

Pedido enviado: Recarregamento da página da aplicação ou consulta direta ao endpoint /api/me.

Resultado esperado: O endpoint /api/me deverá responder com o código HTTP 401 Unauthorized devido à expiração forçada da sessão.

Resultado observado: O servidor validou o parâmetro expires_at na base de dados, confirmou a expiração e retornou o código 401, encerrando o acesso.

Caso 5: Origem inválida na saída
Preparação: Abertura de uma sessão válida na aplicação (em URL_BASE). Abertura de uma origem externa e independente como (https://example.com) no navegador.

Pedido enviado: Execução de um pedido via consola da nova origem:

JavaScript
fetch("URL_BASE/oauth/logout", {
  method: "POST",
  credentials: "include"
});

Resultado esperado: A rota de saída deverá recusar a operação devido à verificação estrita de origem/CORS. O regresso à aba original deverá confirmar que a sessão permanece intacta e válida.

Resultado observado: O mecanismo de segurança bloqueou o pedido cross-origin não autorizado, preservando a integridade e a validade da sessão legítima do utilizador.

Caso 6: Reutilização do cookie revogado
Preparação: Cópia temporária do valor do cookie seguro __Host-session a partir das ferramentas de desenvolvimento numa sessão válida. Execução do logout legítimo (que remove o registo correspondente na base de dados D1) e tentativa posterior de reintroduzir manualmente o mesmo valor de cookie.

Pedido enviado: Consulta ao endpoint /api/me utilizando o cookie anteriormente revogado.

Resultado esperado: Uma vez que a linha correspondente foi eliminada da base de dados D1, a resposta da API deverá ser obrigatoriamente 401 Unauthorized.

Resultado observado: A validação do servidor confirmou que a sessão já não existia no D1, recusando o acesso e retornando o código 401 conforme estipulado.