import crypto from 'node:crypto';
import net from 'node:net';

function cleanReplyText(lines) {
  return lines.join(' ').replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 300);
}

class SmtpConnection {
  constructor(socket, timeoutMs) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    this.buffer = '';
    this.current = null;
    this.replies = [];
    this.waiters = [];
    this.failure = null;

    socket.setEncoding('utf8');
    socket.on('data', (chunk) => this.onData(chunk));
    socket.on('error', (error) => this.fail(error));
    socket.on('close', () => this.fail(new Error('SMTP connection closed')));
  }

  onData(chunk) {
    this.buffer += chunk;
    while (true) {
      const end = this.buffer.indexOf('\n');
      if (end === -1) return;
      const line = this.buffer.slice(0, end + 1).replace(/\r?\n$/, '');
      this.buffer = this.buffer.slice(end + 1);
      const match = /^(\d{3})([ -])(.*)$/.exec(line);
      if (!match) continue;
      const [, rawCode, separator] = match;
      const code = Number(rawCode);
      if (!this.current) this.current = { code, lines: [] };
      this.current.lines.push(line);
      if (separator === ' ' && code === this.current.code) {
        const reply = {
          code,
          lines: this.current.lines,
          message: cleanReplyText(this.current.lines),
        };
        this.current = null;
        this.deliver(reply);
      }
    }
  }

  deliver(reply) {
    const waiter = this.waiters.shift();
    if (waiter) waiter.resolve(reply);
    else this.replies.push(reply);
  }

  fail(error) {
    if (this.failure) return;
    this.failure = error;
    for (const waiter of this.waiters.splice(0)) waiter.reject(error);
  }

  read() {
    if (this.replies.length > 0) return Promise.resolve(this.replies.shift());
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject };
      this.waiters.push(waiter);
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index !== -1) this.waiters.splice(index, 1);
        reject(Object.assign(new Error('SMTP response timeout'), { code: 'ETIMEDOUT' }));
      }, this.timeoutMs);
      timer.unref?.();
      waiter.resolve = (value) => {
        clearTimeout(timer);
        resolve(value);
      };
      waiter.reject = (error) => {
        clearTimeout(timer);
        reject(error);
      };
    });
  }

  async command(command) {
    this.socket.write(`${command}\r\n`);
    return this.read();
  }

  close() {
    if (!this.socket.destroyed) {
      this.socket.end();
      const timer = setTimeout(() => this.socket.destroy(), 250);
      timer.unref?.();
    }
  }
}

function classifyRecipientReply(reply) {
  if (reply.code >= 200 && reply.code < 300) return 'accepted';
  if ([421, 450, 451, 452].includes(reply.code)) return 'greylisted';
  if (reply.code >= 400 && reply.code < 500) return 'temporary_failure';
  if ([550, 551, 553].includes(reply.code)) return 'rejected';
  if (reply.code >= 500) return 'rejected_or_protected';
  return 'unknown';
}

function chooseTarget(mxRecords) {
  return [...mxRecords]
    .filter((record) => record && typeof record.exchange === 'string' && typeof record.address === 'string')
    .sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0))[0] || null;
}

/**
 * Performs an SMTP envelope probe. It never sends DATA or a message body.
 * `mxRecords` must contain pre-resolved, public IP addresses to avoid DNS rebinding.
 */
export async function probeSmtp({
  email,
  mxRecords,
  timeoutMs = 5_000,
  port = 25,
  helloName = 'cleanmail.invalid',
  catchAll = false,
  createConnection = net.createConnection,
}) {
  const target = chooseTarget(mxRecords);
  if (!target) {
    return { status: 'unavailable', reason: 'no_public_mx_address', catch_all: null };
  }

  let session;
  try {
    const socket = createConnection({ host: target.address, port });
    session = new SmtpConnection(socket, timeoutMs);
    const greeting = await session.read();
    if (greeting.code < 200 || greeting.code >= 400) {
      return {
        status: 'unavailable',
        reason: 'smtp_greeting_rejected',
        mx_host: target.exchange,
        mx_ip: target.address,
        response_code: greeting.code,
        response: greeting.message,
        catch_all: null,
      };
    }

    let hello = await session.command(`EHLO ${helloName}`);
    if (hello.code >= 500) hello = await session.command(`HELO ${helloName}`);
    if (hello.code < 200 || hello.code >= 400) {
      return {
        status: 'unavailable',
        reason: 'smtp_hello_rejected',
        mx_host: target.exchange,
        mx_ip: target.address,
        response_code: hello.code,
        response: hello.message,
        catch_all: null,
      };
    }

    const mail = await session.command('MAIL FROM:<>');
    if (mail.code < 200 || mail.code >= 300) {
      return {
        status: mail.code >= 400 && mail.code < 500 ? 'temporary_failure' : 'unavailable',
        reason: 'smtp_mail_from_rejected',
        mx_host: target.exchange,
        mx_ip: target.address,
        response_code: mail.code,
        response: mail.message,
        catch_all: null,
      };
    }

    const recipient = await session.command(`RCPT TO:<${email}>`);
    const status = classifyRecipientReply(recipient);
    let catchAllResult = null;
    if (catchAll && status === 'accepted') {
      const randomLocal = `cleanmail-probe-${crypto.randomBytes(12).toString('hex')}`;
      const domain = email.slice(email.lastIndexOf('@') + 1);
      await session.command('RSET');
      const secondMail = await session.command('MAIL FROM:<>');
      if (secondMail.code >= 200 && secondMail.code < 300) {
        const randomRecipient = await session.command(`RCPT TO:<${randomLocal}@${domain}>`);
        const randomStatus = classifyRecipientReply(randomRecipient);
        if (randomStatus === 'accepted') catchAllResult = true;
        else if (randomStatus === 'rejected' || randomStatus === 'rejected_or_protected') catchAllResult = false;
      }
    }

    session.socket.write('QUIT\r\n');
    return {
      status,
      reason: status === 'accepted' ? 'recipient_accepted_at_rcpt_stage' : 'recipient_not_confirmed',
      mx_host: target.exchange,
      mx_ip: target.address,
      response_code: recipient.code,
      response: recipient.message,
      supports_starttls: hello.lines.some((line) => /(?:^|[ -])STARTTLS(?:\s|$)/i.test(line)),
      catch_all: catchAllResult,
    };
  } catch (error) {
    return {
      status: error?.code === 'ETIMEDOUT' ? 'timeout' : 'unavailable',
      reason: error?.code || 'smtp_connection_error',
      mx_host: target.exchange,
      mx_ip: target.address,
      catch_all: null,
    };
  } finally {
    session?.close();
  }
}
