const express = require("express");
const cors = require("cors");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const db = new sqlite3.Database(":memory:"); // Banco de dados temporário
app.use(express.json());
app.use(cors());

const log = (msg, data) => console.log(`📝 [BACKEND] ${msg}`, data || "");

// Criar tabela de usuários e credenciais
db.serialize(() => {
  db.run(`CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT)`);
  db.run(
    `CREATE TABLE credentials (id TEXT PRIMARY KEY, user_id TEXT, publicKey TEXT, counter INTEGER, transports TEXT)`
  );
  log("📌 Banco de dados inicializado.");
});

// Armazena desafios temporários (idealmente, use Redis ou outro armazenamento)
const challenges = {};

// 📌 Endpoint para iniciar o registro de uma Passkey
app.post("/api/webauthn/register-challenge", async (req, res) => {
  const { userId, username } = req.body;
  log("🔵 Recebido pedido de registro", { userId, username });

  if (!userId || !username) {
    log("❌ Erro: userId ou username ausente.");
    return res.status(400).json({ error: "Faltando userId ou username" });
  }

  // Gerar opções para registro
  const options = await generateRegistrationOptions({
    rpName: "Minha Aplicação",
    rpId: "localhost",
    userName: username,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
      authenticatorAttachment: "platform",
    },
  });

  challenges[userId] = options.challenge;
  log("✅ Desafio de registro gerado", options);

  res.json({ options });
});

// 📌 Endpoint para processar o registro da Passkey
app.post("/api/webauthn/register", async (req, res) => {
  const { userId, credential } = req.body;
  log("🔵 Recebido credencial para registro", { userId, credential });

  if (!userId || !credential) {
    log("❌ Erro: userId ou credential ausente.");
    return res.status(400).json({ error: "Faltando userId ou credential" });
  }

  const expectedChallenge = challenges[userId];

  console.log("expectedChallenge", expectedChallenge);

  try {
    log("⏳ Verificando resposta de registro...");
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: "http://localhost:5173",
      expectedRPID: "localhost",
      requireUserVerification: false, // 🔥
    });

    if (!verification.verified) {
      log("❌ Falha na verificação do registro", verification);
      return res.status(400).json({ error: "Falha na verificação" });
    }

    db.run(
      "INSERT INTO credentials (id, user_id, publicKey, counter, transports) VALUES (?, ?, ?, ?, ?)",
      [
        verification.registrationInfo.credential.id,
        userId,
        verification.registrationInfo.credential.publicKey,
        verification.registrationInfo.credential.counter,
        JSON.stringify(verification.registrationInfo.credential.transports),
      ]
    );
    log("✅ Registro bem-sucedido e credencial salva");

    res.json({ success: true });
  } catch (err) {
    log("❌ Erro ao verificar registro", err);
    res.status(500).json({ error: err.message });
  }
});

// 📌 Endpoint para iniciar a autenticação
app.post("/api/webauthn/authenticate-challenge", async (req, res) => {
  const { userId } = req.body;
  log("🔵 Pedido de autenticação recebido", { userId });

  if (!userId) {
    log("❌ Erro: userId ausente.");
    return res.status(400).json({ error: "Faltando userId" });
  }

  db.get(
    "SELECT id, transports FROM credentials WHERE user_id = ?",
    [userId],
    async (err, row) => {
      if (!row) {
        log("❌ Erro: Usuário não encontrado.");
        return res.status(400).json({ error: "Usuário não encontrado" });
      }

      console.log("row", row);

      const options = await generateAuthenticationOptions({
        rpID: "localhost",
        allowCredentials: [
          { id: row.id, transports: JSON.parse(row.transports) },
        ],
      });

      challenges[userId] = options.challenge;
      log("✅ Desafio de autenticação gerado", options);

      res.json({ options });
    }
  );
});

// 📌 Endpoint para verificar a autenticação
app.post("/api/webauthn/authenticate", async (req, res) => {
  const { userId, assertion } = req.body;
  log("🔵 Recebida resposta de autenticação", { userId, assertion });

  if (!userId || !assertion) {
    log("❌ Erro: userId ou assertion ausente.");
    return res.status(400).json({ error: "Faltando userId ou assertion" });
  }

  const expectedChallenge = challenges[userId];

  db.get(
    "SELECT publicKey, id, counter, transports FROM credentials WHERE user_id = ?",
    [userId],
    async (err, row) => {
      if (!row) {
        log("❌ Erro: Credencial não encontrada.");
        return res.status(400).json({ error: "Credencial não encontrada" });
      }

      console.dir(row, { depth: null });
      console.log("transports", JSON.parse(row.transports));

      try {
        log("⏳ Verificando resposta de autenticação...", {
          response: assertion,
          expectedChallenge,
          expectedOrigin: "http://localhost:5173",
          expectedRPID: "localhost",
          credential: {
            id: row.id,
            publicKey: row.publicKey,
            counter: row.counter,
            transports: JSON.parse(row.transports),
          },
        });
        const verification = await verifyAuthenticationResponse({
          response: assertion,
          expectedChallenge,
          requireUserVerification: false, // 🔥
          expectedOrigin: "http://localhost:5173",
          expectedRPID: "localhost",
          credential: {
            id: row.id,
            publicKey: row.publicKey,
            counter: row.counter,
            transports: JSON.parse(row.transports),
          },
        });

        if (!verification.verified) {
          log("❌ Falha na verificação da autenticação", verification);
          return res.status(400).json({ error: "Falha na autenticação" });
        }

        log("✅ Autenticação bem-sucedida", assertion);
        res.json({ success: true });
      } catch (err) {
        log("❌ Erro ao verificar autenticação", err);
        res.status(500).json({ error: err.message });
      }
    }
  );
});

// Iniciar servidor
const PORT = 3000;
app.listen(PORT, () => log(`🚀 Servidor rodando na porta ${PORT}`));
