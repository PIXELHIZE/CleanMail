import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';

import { probeSmtp } from '../src/cleanmail/smtp.js';

async function smtpServer() {
  const commands = [];
  const server = net.createServer((socket) => {
    socket.setEncoding('utf8');
    socket.write('220 local.test ESMTP\r\n');
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk;
      while (buffer.includes('\n')) {
        const end = buffer.indexOf('\n');
        const command = buffer.slice(0, end + 1).trim();
        buffer = buffer.slice(end + 1);
        commands.push(command);
        if (/^EHLO /i.test(command)) socket.write('250-local.test\r\n250 STARTTLS\r\n');
        else if (/^HELO |^MAIL FROM:|^RSET$/i.test(command)) socket.write('250 ok\r\n');
        else if (/^RCPT TO:<missing@/i.test(command)) socket.write('550 5.1.1 no such user\r\n');
        else if (/^RCPT TO:<grey@/i.test(command)) socket.write('451 4.7.1 try again later\r\n');
        else if (/^RCPT TO:/i.test(command)) socket.write('250 2.1.5 accepted\r\n');
        else if (/^QUIT$/i.test(command)) socket.end('221 bye\r\n');
        else socket.write('500 unknown\r\n');
      }
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, commands, port: server.address().port };
}

test('SMTP probe stops before DATA and can detect catch-all behavior', async () => {
  const fixture = await smtpServer();
  try {
    const result = await probeSmtp({
      email: 'valid@example.test',
      mxRecords: [{ exchange: 'mail.example.test', address: '127.0.0.1', priority: 10 }],
      port: fixture.port,
      timeoutMs: 1_000,
      catchAll: true,
    });
    assert.equal(result.status, 'accepted');
    assert.equal(result.catch_all, true);
    assert.equal(result.supports_starttls, true);
    assert.equal(fixture.commands.some((command) => /^DATA/i.test(command)), false);
  } finally {
    await new Promise((resolve) => fixture.server.close(resolve));
  }
});

test('SMTP probe classifies a permanent RCPT rejection', async () => {
  const fixture = await smtpServer();
  try {
    const result = await probeSmtp({
      email: 'missing@example.test',
      mxRecords: [{ exchange: 'mail.example.test', address: '127.0.0.1', priority: 10 }],
      port: fixture.port,
      timeoutMs: 1_000,
    });
    assert.equal(result.status, 'rejected');
    assert.equal(result.response_code, 550);
    assert.equal(fixture.commands.some((command) => /^DATA/i.test(command)), false);
  } finally {
    await new Promise((resolve) => fixture.server.close(resolve));
  }
});

test('SMTP 4xx recipient response is classified as greylisting, not rejection', async () => {
  const fixture = await smtpServer();
  try {
    const result = await probeSmtp({
      email: 'grey@example.test',
      mxRecords: [{ exchange: 'mail.example.test', address: '127.0.0.1', priority: 10 }],
      port: fixture.port,
      timeoutMs: 1_000,
    });
    assert.equal(result.status, 'greylisted');
    assert.equal(result.response_code, 451);
  } finally {
    await new Promise((resolve) => fixture.server.close(resolve));
  }
});
