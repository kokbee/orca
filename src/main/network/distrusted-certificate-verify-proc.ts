import { app, type Session } from 'electron'
import { isDistrustedTlsCertificate } from '../../shared/distrusted-tls-certificates'

// -206 is ERR_CERT_REVOKED, which the certificate-error handler never offers to bypass.
const ERR_CERT_REVOKED = -206
// Keeps Chromium's own verdict, Certificate Transparency included.
const USE_CHROMIUM_RESULT = -3
const MAX_CHAIN_LENGTH = 16

type CertificateChainLink = { data: string; issuerCert?: CertificateChainLink }
type VerifiedChainRequest = { errorCode: number; validatedCertificate?: CertificateChainLink }

function chainHasDistrustedKey(leaf: CertificateChainLink | undefined): boolean {
  let certificate = leaf
  for (let depth = 0; certificate && depth < MAX_CHAIN_LENGTH; depth++) {
    if (isDistrustedTlsCertificate(certificate.data)) {
      return true
    }
    certificate = certificate.issuerCert
  }
  return false
}

function verifyAgainstDistrustedKeys(
  request: VerifiedChainRequest,
  callback: (verificationResult: number) => void
): void {
  const distrusted = request.errorCode === 0 && chainHasDistrustedKey(request.validatedCertificate)
  callback(distrusted ? ERR_CERT_REVOKED : USE_CHROMIUM_RESULT)
}

// Why session-created: it fires for defaultSession and every partition (browser profiles,
// doc preview, updater) once registered before ready, so no session skips the check.
export function installDistrustedCertificateVerifyProc(): void {
  app.on('session-created', (created: Session) => {
    created.setCertificateVerifyProc(verifyAgainstDistrustedKeys)
  })
}
