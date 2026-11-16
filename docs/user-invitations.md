# Convites da Vetorial

Implementação N4, 16/11/2026. Especificação canônica no projeto de atividades,
`Vetorial - Evo CRM Agentes/entregas/N2-spec-convite.md`, com correções N3.

## Operação e implantação

- Migração auth **ímpar** `20261116120001`, aditiva e reexecutável. Validar que
  `users` é UUID na conexão/schema compartilhado com CRM. Aplicar antes de auth/worker.
- `USER_INVITATIONS_ENABLED=false` por padrão. Desabilitado: reenvio e criação sem
  senha retornam 503; cadastro com senha e recuperação de contas comuns continuam.
- `USER_INVITATIONS_RECIPIENT_ALLOWLIST=ricardohenrique@agenciavetorial.com` restringe
  o worker durante o único smoke autorizado. Usar conta sintética identificada;
  não redefinir a senha da conta real de Ricardo. Nenhum replay de legado.
- GET autenticado `/api/v1/users/invitation_capabilities` devolve
  `data.user_invitations_enabled`, combinado com permissão administrativa.
- O worker deve executar a mesma imagem/configuração de auth. O sweeper inicia no
  startup Sidekiq, varre a outbox a cada 60 segundos e funciona sem Redis para
  expiração/watchdog. O envio exige Redis e flag habilitada. Não limpar filas comuns.
- SMTP em **N8**, pelo Portainer, com backup: alterar `SMTP_AUTHENTICATION` de LOGIN
  para PLAIN em `installation_configs` do **auth (`00_evo_auth`)**. Configuração
  efetiva vem de banco antes de ENV. `SMTP_PASSWORD_SECRET` é o valor direto da
  credencial, **não** caminho de arquivo Docker Secret. Não imprimir seu conteúdo.
- Alinhar auth/Sidekiq: 587, STARTTLS, certificado verificado, remetente
  `envio-automatico@agenciavetorial.com`, FRONTEND_URL exata
  `https://evo.agenciavetorial.com`. Não aplicar `SMTP_SSL=true` na porta 587.
- Em produção, rollback mantém migração: flag off, cancelar queued, aguardar sends,
  invalidar os digests dos pending sob lock, preservar auditoria, restaurar imagens
  por digest/compose SMTP conforme backup. `down` é somente ensaio local sintético.

## Contrato para N5

- POST `/api/v1/users/:id/resend_invite`: identidade humana, users.manage **e**
  users.update; serviço não passa. Resposta 202 contém user_id, invitation_status,
  delivery_status=queued, request_id e next_resend_at. Não significa entrega.
- GET lista continua users.read. Só administradores recebem invitation_status,
  invitation_sent_at, invitation_last_requested_at, invitation_delivery_status,
  invitation_error_code, invitation_request_id, next_resend_at, can_resend_invite.
  Selo pendente deriva de `pending`, independente de `confirmed`.
- 409: INVITE_IN_PROGRESS/INVITE_NOT_ELIGIBLE; 429: INVITE_RATE_LIMITED com
  Retry-After e `error.details.next_resend_at`; 503: INVITATIONS_DISABLED ou
  INVITE_QUEUE_UNAVAILABLE. Erros SMTP nunca retornam detalhes do servidor.
- Bulk: no máximo 50 entradas, trim/downcase/dedup, count é total criado;
  invited_users/failed_invitations representam processamento, nunca recebimento.
- Criar extrai `data.user`. Senha explícita não envia convite. E-mail existente
  não muda papel/senha nem é reenviado implicitamente. Papel desconhecido ou além
  dos grants do ator é recusado; não há fallback silencioso para papel agent.
- Recuperação API e Devise retorna 202 genérico, assíncrono e limitado. Ignora
  redirect_url do cliente; origem HTTPS fixa. GET do link não consome token.
- N5: polling 5s (N3 A1), teto 2min; remover query sensível do histórico, sem
  analytics/recursos externos na página, Referrer-Policy no-referrer e supressão
  da query nos logs do proxy/frontend antes de ativar SMTP.

## Garantias e limites

Token Devise válido 6h, só digest persistido. Reserva invalida o anterior sob lock.
Outbox e args de convite contêm somente IDs. APM recebe wrapper redigido para token;
logger UserMailer não emite MIME. Recuperação comum enfileira endereço cifrado,
limiters usam HMAC do e-mail. Envio local faz I/O sob lock user→delivery, com
lock_timeout 30s, open_timeout 10s, read/write_timeout 15s. O lock tem statement
budget explícito 35s. Aceite SMTP pode preceder falha de commit: estado uncertain,
sem retry automático. Watchdog: sending 2min; queued órfão falha em 10min.

Autenticação OAuth converge no callback de AccessToken; Devise token-auth usa
User#create_token. Só emissão de sessão aceita o convite; desafio MFA não aceita.
Reset público, Devise, perfil e admin serializam alterações de senha/token. Reset
revoga OAuth/cache e tokens Devise. Legado permanece not_invited sem heurística.

Testes usam PostgreSQL/Redis locais isolados e SMTP sink em 127.0.0.1. A suíte deve
usar banco criado pelo schema, sem os seeds persistentes da migração inicial;
algumas fixtures preexistentes criam roles com as mesmas chaves desses seeds.
