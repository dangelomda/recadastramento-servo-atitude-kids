// test-db.js
require('dotenv').config();
const { Pool } = require('pg');

// Usamos EXATAMENTE a mesma configuração do seu server.js
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

async function testConnection() {
  console.log('Tentando conectar ao banco de dados...');
  let client;
  try {
    client = await pool.connect();
    console.log('✅ Conexão estabelecida com sucesso!');
    
    const result = await client.query('SELECT NOW()');
    console.log('⏰ Horário do servidor do banco de dados:', result.rows[0].now);

  } catch (err) {
    console.error('❌ FALHA AO CONECTAR!');
    console.error(err); // Imprime o erro completo
  } finally {
    if (client) {
      client.release(); // Libera o cliente de volta para o pool
    }
    await pool.end(); // Fecha todas as conexões do pool
    console.log('Conexão encerrada.');
  }
}

testConnection();