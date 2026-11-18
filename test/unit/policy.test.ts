import { describe, expect, it } from 'vitest';
import { disallowed, isAllowed, matchesPattern } from '../../src/policy/address.js';
import { decideInbound } from '../../src/policy/inbound.js';
import { evaluateSenderAuth } from '../../src/policy/sender-auth.js';

describe('address matching', () => {
  it('matches exact addresses case-insensitively', () => {
    expect(matchesPattern('you@example.net', 'you@example.net')).toBe(true);
    expect(matchesPattern('other@example.net', 'you@example.net')).toBe(false);
  });

  it('matches *@domain only for that exact domain', () => {
    expect(matchesPattern('a@example.org', '*@example.org')).toBe(true);
    expect(matchesPattern('a@mail.example.org', '*@example.org')).toBe(false);
    expect(matchesPattern('a@evilexample.org', '*@example.org')).toBe(false);
  });

  it('matches any address with *', () => {
    expect(matchesPattern('a@example.org', '*')).toBe(true);
    expect(matchesPattern('not-an-address', '*')).toBe(false);
  });

  it('isAllowed is false for an empty list', () => {
    expect(isAllowed('a@b.de', [])).toBe(false);
  });

  it('disallowed returns unique offending addresses', () => {
    expect(disallowed(['a@ok.de', 'X@bad.de', 'x@bad.de'], ['*@ok.de'])).toEqual(['x@bad.de']);
  });
});

describe('evaluateSenderAuth', () => {
  it('passes on dmarc=pass', () => {
    expect(
      evaluateSenderAuth(['mx.example; dmarc=pass header.from=example.net'], 'a@example.net'),
    ).toBe('pass');
  });

  it('fails on dmarc=fail even if dkim passes', () => {
    const h = 'mx; dkim=pass header.d=example.net; dmarc=fail (p=reject) header.from=example.net';
    expect(evaluateSenderAuth([h], 'a@example.net')).toBe('fail');
  });

  it('uses aligned dkim or spf when there is no dmarc result', () => {
    expect(evaluateSenderAuth(['mx; dkim=pass header.d=example.net'], 'a@example.net')).toBe(
      'pass',
    );
    expect(
      evaluateSenderAuth(['mx; spf=pass smtp.mailfrom=bounce@example.net'], 'a@example.net'),
    ).toBe('pass');
    expect(evaluateSenderAuth(['mx; dkim=pass header.d=other.com'], 'a@example.net')).toBe('fail');
  });

  it('only looks at the top-most header', () => {
    expect(evaluateSenderAuth(['mx; dmarc=fail', 'forged; dmarc=pass'], 'a@example.net')).toBe(
      'fail',
    );
  });

  it('reports missing when there is no header', () => {
    expect(evaluateSenderAuth([], 'a@example.net')).toBe('missing');
  });

  it('accepts several trusted servers', () => {
    const h = ['forged; dmarc=fail', 'mx2.example; dmarc=pass'];
    expect(evaluateSenderAuth(h, 'a@example.net', ['mx1.example', 'mx2.example'])).toBe('pass');
  });
});

describe('ARC results', () => {
  const cfg = {
    allow_receive_from: ['boss@test.local'],
    require_sender_auth: true,
    trusted_authserv_id: ['mx1.fwd.example'],
  };
  const arc = (v: string) => ({ from: 'boss@test.local', authResults: [], arcAuthResults: [v] });

  it('are ignored unless trust_arc is on', () => {
    expect(decideInbound(cfg, arc('mx1.fwd.example; dmarc=pass'))).toEqual({
      allowed: false,
      reason: 'sender_auth_missing',
    });
  });

  it('count from the trusted server with trust_arc', () => {
    const on = { ...cfg, trust_arc: true };
    expect(decideInbound(on, arc('mx1.fwd.example; dmarc=pass'))).toEqual({ allowed: true });
    expect(decideInbound(on, arc('mx1.fwd.example; dmarc=fail'))).toEqual({
      allowed: false,
      reason: 'sender_auth_failed',
    });
    expect(decideInbound(on, arc('other.example; dmarc=pass'))).toEqual({
      allowed: false,
      reason: 'sender_auth_missing',
    });
  });

  it('come after Authentication-Results from the same server', () => {
    const on = { ...cfg, trust_arc: true };
    const msg = {
      from: 'boss@test.local',
      authResults: ['mx1.fwd.example; dmarc=fail'],
      arcAuthResults: ['mx1.fwd.example; dmarc=pass'],
    };
    expect(decideInbound(on, msg)).toEqual({ allowed: false, reason: 'sender_auth_failed' });
  });
});

describe('decideInbound', () => {
  const cfg = { allow_receive_from: ['boss@test.local'], require_sender_auth: true };

  it('allows an allowed, authenticated sender', () => {
    expect(
      decideInbound(cfg, { from: 'Boss@Test.local', authResults: ['mx; dmarc=pass'] }),
    ).toEqual({ allowed: true });
  });

  it('rejects senders not on the list before checking auth', () => {
    expect(decideInbound(cfg, { from: 'x@test.local', authResults: [] })).toEqual({
      allowed: false,
      reason: 'sender_not_allowed',
    });
  });

  it('rejects a missing From header', () => {
    expect(decideInbound(cfg, { from: null, authResults: [] })).toEqual({
      allowed: false,
      reason: 'sender_not_allowed',
    });
  });

  it('distinguishes missing and failed auth', () => {
    expect(decideInbound(cfg, { from: 'boss@test.local', authResults: [] })).toEqual({
      allowed: false,
      reason: 'sender_auth_missing',
    });
    expect(
      decideInbound(cfg, { from: 'boss@test.local', authResults: ['mx; dmarc=fail'] }),
    ).toEqual({ allowed: false, reason: 'sender_auth_failed' });
  });

  it('with receive_for, ignores mail delivered to other addresses before anything else', () => {
    const shared = { ...cfg, receive_for: ['agent@test.local', '*@agents.test'] };
    const msg = { from: 'boss@test.local', authResults: ['mx; dmarc=pass'] };
    expect(decideInbound(shared, { ...msg, deliveredTo: 'agent@test.local' })).toEqual({
      allowed: true,
    });
    expect(decideInbound(shared, { ...msg, deliveredTo: 'x@agents.test' })).toEqual({
      allowed: true,
    });
    for (const deliveredTo of ['other@test.local', null]) {
      expect(decideInbound(shared, { ...msg, from: 'x@evil.local', deliveredTo })).toEqual({
        allowed: false,
        reason: 'other_recipient',
      });
    }
  });

  it('skips auth when require_sender_auth is false', () => {
    expect(
      decideInbound(
        { ...cfg, require_sender_auth: false },
        { from: 'boss@test.local', authResults: [] },
      ),
    ).toEqual({ allowed: true });
  });
});
