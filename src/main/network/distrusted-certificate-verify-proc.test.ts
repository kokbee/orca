import { X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import * as tls from 'node:tls'
import { beforeEach, describe, expect, it, vi } from 'vitest'

type ChainLink = { data: string; issuerCert?: ChainLink }
type VerifyProc = (
  request: { errorCode: number; validatedCertificate?: ChainLink },
  callback: (result: number) => void
) => void

const { sessionCreatedListeners } = vi.hoisted(() => {
  const listeners: ((session: unknown) => void)[] = []
  return { sessionCreatedListeners: listeners }
})

vi.mock('electron', () => ({
  app: {
    on: (event: string, listener: (session: unknown) => void) => {
      if (event === 'session-created') {
        sessionCreatedListeners.push(listener)
      }
    }
  }
}))

import { installDistrustedCertificateVerifyProc } from './distrusted-certificate-verify-proc'

const distrustedFixture = (
  readFileSync(
    join(__dirname, '../../shared/__fixtures__/distrusted-emsign-certificates.pem'),
    'utf8'
  ).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []
).map((pem) => ({ pem, certificate: new X509Certificate(pem) }))

function distrusted(match: (certificate: X509Certificate) => boolean): string {
  const found = distrustedFixture.find((entry) => match(entry.certificate))
  if (!found) {
    throw new Error('fixture certificate missing')
  }
  return found.pem
}

function trustedRoot(commonName: string): string {
  const pem = tls.rootCertificates.find(
    (candidate) => new X509Certificate(candidate).subject.match(/^CN=(.+)$/m)?.[1] === commonName
  )
  if (!pem) {
    throw new Error(`missing root ${commonName}`)
  }
  return pem
}

function chain(...pems: string[]): ChainLink | undefined {
  return pems.reduceRight<ChainLink | undefined>(
    (issuerCert, data) => (issuerCert ? { data, issuerCert } : { data }),
    undefined
  )
}

function sessionVerifyProc(): VerifyProc {
  let installed: VerifyProc | null = null
  const createdSession = {
    setCertificateVerifyProc: (proc: VerifyProc) => {
      installed = proc
    }
  }
  for (const listener of sessionCreatedListeners) {
    listener(createdSession)
  }
  if (!installed) {
    throw new Error('no verify proc installed for the created session')
  }
  return installed
}

function verify(validatedCertificate: ChainLink | undefined, errorCode = 0): number | undefined {
  let result: number | undefined
  sessionVerifyProc()({ validatedCertificate, errorCode }, (value) => {
    result = value
  })
  return result
}

describe('installDistrustedCertificateVerifyProc', () => {
  const leafStandIn = trustedRoot('ISRG Root X2')
  const crossSignedIntermediate = distrusted((certificate) =>
    certificate.issuer.includes('CN=AAA Certificate Services')
  )
  const nssRemovedRoot = distrusted((certificate) =>
    certificate.subject.includes('CN=emSign ECC Root CA - G3')
  )

  beforeEach(() => {
    sessionCreatedListeners.length = 0
    installDistrustedCertificateVerifyProc()
  })

  it('revokes a chain Chromium accepted through a compromised cross-signed intermediate', () => {
    expect(verify(chain(leafStandIn, crossSignedIntermediate))).toBe(-206)
  })

  it('revokes a chain Chromium accepted under a root NSS removed', () => {
    expect(verify(chain(leafStandIn, nssRemovedRoot))).toBe(-206)
  })

  it("keeps Chromium's verdict for unaffected chains and chains it already rejected", () => {
    expect(verify(chain(leafStandIn, trustedRoot('ISRG Root X1')))).toBe(-3)
    expect(verify(chain(leafStandIn, crossSignedIntermediate), -202)).toBe(-3)
  })
})
