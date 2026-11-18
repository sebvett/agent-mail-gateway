import { describe, expect, it } from 'vitest';
import { decodeMessageId, encodeMessageId } from '../../src/mail/ids.js';
import { parseMessage } from '../../src/mail/parse.js';
import { buildRaw } from '../helpers/mail.js';

describe('message ids', () => {
  it('round-trips', () => {
    expect(decodeMessageId(encodeMessageId('123', 45))).toEqual({ uidValidity: '123', uid: 45 });
  });
  it('rejects junk', () => {
    expect(decodeMessageId('../etc')).toBeNull();
    expect(decodeMessageId('1-0')).toBeNull();
  });
});

describe('parseMessage', () => {
  it('extracts addresses lowercased, markdown body, preview and attachments', async () => {
    const raw = await buildRaw({
      from: '"Alex" <you@example.net>',
      to: 'Agent <agent@test.local>',
      subject: 'Report',
      html: '<p>Hello <b>agent</b></p>',
      messageId: '<m1@example.net>',
      headers: { 'Authentication-Results': 'mx.test; dmarc=pass header.from=example.net' },
      attachments: [{ filename: 'a.txt', content: 'abc', contentType: 'text/plain' }],
    });
    const p = await parseMessage(raw);
    expect(p.from).toBe('you@example.net');
    expect(p.fromName).toBe('Alex');
    expect(p.to).toEqual(['agent@test.local']);
    expect(p.subject).toBe('Report');
    expect(p.messageId).toBe('<m1@example.net>');
    expect(p.bodyMarkdown).toBe('Hello **agent**');
    expect(p.preview).toBe('Hello **agent**');
    expect(p.authResults).toEqual(['mx.test; dmarc=pass header.from=example.net']);
    expect(p.attachments).toMatchObject([
      { index: 0, filename: 'a.txt', contentType: 'text/plain', size: 3 },
    ]);
  });

  it('takes the delivery address from the top-most delivery header', async () => {
    const raw = Buffer.from(
      'X-Original-To: Culture@Agents.example\r\nDelivered-To: <other@agents.example>\r\n' +
        'From: a@example.net\r\nTo: someone@else.example\r\n\r\nbody\r\n',
    );
    expect((await parseMessage(raw)).deliveredTo).toBe('culture@agents.example');
    const none = Buffer.from('From: a@example.net\r\nTo: b@example.net\r\n\r\nbody\r\n');
    expect((await parseMessage(none)).deliveredTo).toBeNull();
  });

  it('falls back to the text part and tolerates a missing From', async () => {
    const raw = Buffer.from('Subject: no from\r\n\r\nplain body\r\n');
    const p = await parseMessage(raw);
    expect(p.from).toBeNull();
    expect(p.bodyMarkdown).toBe('plain body');
    expect(p.attachments).toEqual([]);
  });
});
